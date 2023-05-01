use crate::{PublicKeyVt, SignatureVt};
use bls12_381_plus::{
    ff::Field,
    group::{Curve, Group},
    multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective, Scalar,
};
use core::fmt::{self, Display, Formatter};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// A signature proof of knowledge
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ProofOfKnowledgeVt {
    /// x \cdot A
    pub u: G2Projective,
    /// V = -(x + y)((s - \alpha)\cdot A + \alpha \cdot A)
    pub v: G2Projective,
}

impl Display for ProofOfKnowledgeVt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{{ u: {}, v: {} }}", self.u, self.v)
    }
}

impl ConditionallySelectable for ProofOfKnowledgeVt {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            u: G2Projective::conditional_select(&a.u, &b.u, choice),
            v: G2Projective::conditional_select(&a.v, &b.v, choice),
        }
    }
}

impl ProofOfKnowledgeVt {
    /// The number of bytes required for this proof
    pub const BYTES: usize = G2Projective::COMPRESSED_BYTES * 2;

    /// Check if this is valid
    pub fn is_valid(&self) -> Choice {
        !self.u.is_identity() | self.u.is_on_curve() | !self.v.is_identity() | self.v.is_on_curve()
    }

    /// Check if this is invalid
    pub fn is_invalid(&self) -> Choice {
        self.u.is_identity() | !self.u.is_on_curve() | self.v.is_identity() | !self.v.is_on_curve()
    }

    /// Verify the proof of knowledge
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKeyVt, msg: B, y: Scalar) -> Choice {
        if (self.is_invalid() | pk.is_invalid()).unwrap_u8() == 1u8 {
            return 0u8.into();
        }
        if y.is_zero().unwrap_u8() == 1u8 {
            return 0u8.into();
        }
        let a = SignatureVt::hash_msg(msg.as_ref());
        let g1 = G1Affine::generator();
        let uay = self.u + a * y;

        multi_miller_loop(&[
            (&g1, &G2Prepared::from(self.v.to_affine())),
            (&pk.0.to_affine(), &G2Prepared::from(uay.to_affine())),
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
        let uu = G2Affine::from_compressed(
            &<[u8; G2Projective::COMPRESSED_BYTES]>::try_from(&bytes[..Self::BYTES / 2]).unwrap(),
        )
        .map(G2Projective::from);
        let vv = G2Affine::from_compressed(
            &<[u8; G2Projective::COMPRESSED_BYTES]>::try_from(&bytes[Self::BYTES / 2..]).unwrap(),
        )
        .map(G2Projective::from);
        uu.and_then(|u| vv.and_then(|v| CtOption::new(Self { u, v }, Choice::from(1u8))))
    }

    #[cfg(feature = "iso8601-timestamp")]
    pub(crate) fn generate_timestamp_based_y(u: G2Projective) -> (Scalar, i64) {
        let t = iso8601_timestamp::Timestamp::now_utc()
            .duration_since(iso8601_timestamp::Timestamp::UNIX_EPOCH)
            .whole_milliseconds() as i64;
        (Self::compute_y(u, t), t)
    }

    #[cfg(feature = "iso8601-timestamp")]
    pub(crate) fn compute_y(u: G2Projective, t: i64) -> Scalar {
        const DST: &[u8] = b"BLS12381G2-SIG-PROOF-OF-KNOWLEDGE-TIMESTAMP-";
        const INFO: [u8; 2] = [0u8, 48u8];

        let mut y_bytes = [0u8; 104];
        y_bytes[..96].copy_from_slice(&u.to_affine().to_compressed());
        y_bytes[96..].copy_from_slice(&t.to_le_bytes());
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
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct ProofOfKnowledgeVtTimestamp {
    /// The signature proof of knowledge
    pub pok: ProofOfKnowledgeVt,
    /// The timestamp for this proof
    pub t: i64,
}

#[cfg(feature = "iso8601-timestamp")]
impl ProofOfKnowledgeVtTimestamp {
    /// The number of bytes required for this proof
    pub const BYTES: usize = ProofOfKnowledgeVt::BYTES + 8;

    /// Create a proof of knowledge based ona timestamp instead of a
    /// server challenge
    pub fn new<B: AsRef<[u8]>>(msg: B, sig: SignatureVt) -> Option<ProofOfKnowledgeVtTimestamp> {
        if sig.is_invalid().unwrap_u8() == 1u8 {
            return None;
        }
        let x = Scalar::random(rand_core::OsRng);
        if x.is_zero().unwrap_u8() == 1u8 {
            return None;
        }
        let a = SignatureVt::hash_msg(msg.as_ref());
        if a.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        let u = a * x;
        if u.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        let (y, t) = ProofOfKnowledgeVt::generate_timestamp_based_y(u);
        if y.is_zero().unwrap_u8() == 1u8 {
            return None;
        }

        let v = sig.0 * (x + y);
        if v.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        Some(Self {
            pok: ProofOfKnowledgeVt { u, v: -v },
            t,
        })
    }

    /// Verify the proof of knowledge
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKeyVt, msg: B, timeout_ms: i64) -> Choice {
        let now = iso8601_timestamp::Timestamp::now_utc();
        let since = iso8601_timestamp::Timestamp::UNIX_EPOCH
            .saturating_add(iso8601_timestamp::Duration::milliseconds(self.t));
        let elapsed = now.duration_since(since).whole_milliseconds() as i64;
        if elapsed > timeout_ms {
            return 0u8.into();
        }

        let y = ProofOfKnowledgeVt::compute_y(self.pok.u, self.t);
        self.pok.verify(pk, msg, y)
    }

    /// Get the byte representation
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[..ProofOfKnowledgeVt::BYTES].copy_from_slice(&self.pok.to_bytes());
        bytes[ProofOfKnowledgeVt::BYTES..].copy_from_slice(&self.t.to_be_bytes());
        bytes
    }

    /// Convert a big-endian representation
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        let pok_bytes = arrayref::array_ref![bytes, 0, ProofOfKnowledgeVt::BYTES];
        let ct_pok = ProofOfKnowledgeVt::from_bytes(pok_bytes);
        if ct_pok.is_none().unwrap_u8() == 1u8 {
            return CtOption::new(Self::default(), Choice::from(0u8));
        }

        let t =
            i64::from_be_bytes(<[u8; 8]>::try_from(&bytes[ProofOfKnowledgeVt::BYTES..]).unwrap());
        ct_pok.map(|pok| Self { pok, t })
    }
}

#[test]
fn proof_vt_works() {
    use crate::*;
    use rand_core::SeedableRng;

    let mut rng = MockRng::from_seed([3u8; 16]);
    let sk = SecretKey::hash(b"proof_test");
    let pk = PublicKeyVt::from(&sk);
    let msg = b"proof_test_msg";
    let sig = SignatureVt::new(&sk, msg).unwrap();

    let x = Scalar::random(&mut rng);
    let y = Scalar::random(&mut rng);

    let opt_commitment = ProofCommitmentVt::from_msg_with_x(msg, x);
    assert!(opt_commitment.is_some());
    let commitment = opt_commitment.unwrap();
    let opt_proof = commitment.complete(x, y, sig);
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
        let opt_proof = ProofOfKnowledgeVtTimestamp::new(msg, sig);
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
    let proof = ProofOfKnowledgeVt {
        u: G2Projective::random(&mut rng),
        v: G2Projective::random(&mut rng),
    };

    let proof_bytes = serde_bare::to_vec(&proof).unwrap();
    let res_de_proof = serde_bare::from_slice::<ProofOfKnowledgeVt>(&proof_bytes);
    assert!(res_de_proof.is_ok());
    let de_proof = res_de_proof.unwrap();
    assert_eq!(de_proof, proof);

    let proof_str = serde_json::to_string(&proof).unwrap();
    let res_de_proof = serde_json::from_str::<ProofOfKnowledgeVt>(&proof_str);
    assert!(res_de_proof.is_ok());
    let de_proof = res_de_proof.unwrap();
    assert_eq!(de_proof, proof);
}
