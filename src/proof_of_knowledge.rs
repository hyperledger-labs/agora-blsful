use crate::{PublicKey, Signature};
use bls12_381_plus::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, Scalar};
use core::fmt::{self, Display, Formatter};
use ff::Field;
use group::{Curve, Group};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// A signature proof of knowledge
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ProofOfKnowledge {
    /// x \cdot A
    pub u: G1Projective,
    /// V = -(x + y)((s - \alpha)\cdot A + \alpha \cdot A)
    pub v: G1Projective,
}

impl Display for ProofOfKnowledge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{{ u: {}, v: {} }}", self.u, self.v)
    }
}

impl ConditionallySelectable for ProofOfKnowledge {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            u: G1Projective::conditional_select(&a.u, &b.u, choice),
            v: G1Projective::conditional_select(&a.v, &b.v, choice),
        }
    }
}

impl ProofOfKnowledge {
    /// The number of bytes required for this proof
    pub const BYTES: usize = 96;

    /// Check if this is valid
    pub fn is_valid(&self) -> Choice {
        !self.u.is_identity() | self.u.is_on_curve() | !self.v.is_identity() | self.v.is_on_curve()
    }

    /// Check if this is invalid
    pub fn is_invalid(&self) -> Choice {
        self.u.is_identity() | !self.u.is_on_curve() | self.v.is_identity() | !self.v.is_on_curve()
    }

    /// Verify the proof of knowledge
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKey, msg: B, y: Scalar) -> Choice {
        if (self.is_invalid() | pk.is_invalid()).unwrap_u8() == 1u8 {
            return 0u8.into();
        }
        if y.is_zero().unwrap_u8() == 1u8 {
            return 0u8.into();
        }
        let a = Signature::hash_msg(msg.as_ref());
        let g2 = G2Affine::generator();
        let uay = self.u + a * y;

        multi_miller_loop(&[
            (&self.v.to_affine(), &G2Prepared::from(g2)),
            (&uay.to_affine(), &G2Prepared::from(pk.0.to_affine())),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Get the byte representation
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[..Self::BYTES / 2].copy_from_slice(&self.u.to_affine().to_compressed());
        bytes[Self::BYTES / 2..].copy_from_slice(&self.v.to_affine().to_compressed());
        bytes
    }

    /// Convert a big-endian representation
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        let uu =
            G1Affine::from_compressed(&<[u8; 48]>::try_from(&bytes[..Self::BYTES / 2]).unwrap())
                .map(G1Projective::from);
        let vv =
            G1Affine::from_compressed(&<[u8; 48]>::try_from(&bytes[Self::BYTES / 2..]).unwrap())
                .map(G1Projective::from);
        uu.and_then(|u| vv.and_then(|v| CtOption::new(Self { u, v }, Choice::from(1u8))))
    }

    #[cfg(feature = "iso8601-timestamp")]
    pub(crate) fn generate_timestamp_based_y(u: G1Projective) -> (Scalar, i64) {
        let t = iso8601_timestamp::Timestamp::now_utc()
            .duration_since(iso8601_timestamp::Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64;
        (Self::compute_y(u, t), t)
    }

    #[cfg(feature = "iso8601-timestamp")]
    pub(crate) fn compute_y(u: G1Projective, t: i64) -> Scalar {
        const DST: &[u8] = b"BLS12381G1-SIG-PROOF-OF-KNOWLEDGE-TIMESTAMP-";
        const INFO: [u8; 2] = [0u8, 48u8];

        let mut y_bytes = [0u8; 56];
        y_bytes[..48].copy_from_slice(&u.to_affine().to_compressed());
        y_bytes[48..].copy_from_slice(&t.to_le_bytes());
        let mut extractor = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(DST));
        extractor.input_ikm(&y_bytes);
        extractor.input_ikm(&[0u8]);
        let (_, h) = extractor.finalize();

        let mut output = [0u8; 48];
        // 48 bytes is acceptable length so `unwrap` is okay
        h.expand(&INFO, &mut output).unwrap();
        Scalar::from_okm(&output)
    }
}

#[cfg(feature = "iso8601-timestamp")]
/// A signature proof of knowledge where the
/// challenge is derived from a timestamp
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ProofOfKnowledgeTimestamp {
    /// The signature proof of knowledge
    pub pok: ProofOfKnowledge,
    /// The timestamp for this proof
    pub t: i64,
}

#[cfg(feature = "iso8601-timestamp")]
impl ProofOfKnowledgeTimestamp {
    /// Verify the proof of knowledge
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKey, msg: B, timeout_ms: i64) -> Choice {
        let now = iso8601_timestamp::Timestamp::now_utc();
        let since = iso8601_timestamp::Timestamp::UNIX_EPOCH
            .saturating_add(iso8601_timestamp::Duration::milliseconds(self.t));
        let elapsed = now.duration_since(since).whole_milliseconds() as i64;
        if elapsed > timeout_ms {
            return 0u8.into();
        }

        let y = ProofOfKnowledge::compute_y(self.pok.u, self.t);
        self.pok.verify(pk, msg, y)
    }
}

#[test]
fn proof_works() {
    use crate::*;
    use rand_core::SeedableRng;

    let mut rng = MockRng::from_seed([3u8; 16]);
    let sk = SecretKey::hash(b"proof_test").unwrap();
    let pk = PublicKey::from(&sk);
    let msg = b"proof_test_msg";
    let sig = Signature::new(&sk, msg).unwrap();

    let x = Scalar::random(&mut rng);
    let y = Scalar::random(&mut rng);

    let opt_proof = sig.proof_of_knowledge(msg, x, y);
    assert!(opt_proof.is_some());
    let mut proof = opt_proof.unwrap();
    assert_eq!(proof.verify(pk, msg, y).unwrap_u8(), 1u8);

    assert_eq!(proof.verify(pk, b"different message", y).unwrap_u8(), 0u8);
    assert_eq!(proof.verify(pk, msg, x).unwrap_u8(), 0u8);
    assert_eq!(proof.verify(pk, msg, sk.0).unwrap_u8(), 0u8);

    // Can't be replayed in another context
    let t = Scalar::random(&mut rng);
    proof.v *= t;
    proof.u *= t;
    assert_eq!(proof.verify(pk, msg, y).unwrap_u8(), 0u8);

    #[cfg(feature = "iso8601-timestamp")]
    {
        let opt_proof = sig.proof_of_knowledge_with_timestamp(msg, x);
        assert!(opt_proof.is_some());
        let mut proof = opt_proof.unwrap();
        assert_eq!(proof.verify(pk, msg, 2000).unwrap_u8(), 1u8);
        proof.pok.u *= t;
        proof.pok.v *= t;
        assert_eq!(proof.verify(pk, msg, 2000).unwrap_u8(), 0u8);
    }
}

#[test]
fn proof_serialization() {
    use rand_core::SeedableRng;

    let mut rng = crate::MockRng::from_seed([7u8; 16]);
    let proof = ProofOfKnowledge {
        u: G1Projective::random(&mut rng),
        v: G1Projective::random(&mut rng),
    };

    let proof_bytes = serde_bare::to_vec(&proof).unwrap();
    let res_de_proof = serde_bare::from_slice::<ProofOfKnowledge>(&proof_bytes);
    assert!(res_de_proof.is_ok());
    let de_proof = res_de_proof.unwrap();
    assert_eq!(de_proof, proof);

    let proof_str = serde_json::to_string(&proof).unwrap();
    let res_de_proof = serde_json::from_str::<ProofOfKnowledge>(&proof_str);
    assert!(res_de_proof.is_ok());
    let de_proof = res_de_proof.unwrap();
    assert_eq!(de_proof, proof);
}
