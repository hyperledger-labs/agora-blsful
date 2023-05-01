use crate::{PublicKeyVt, SecretKey};
use bls12_381_plus::{
    elliptic_curve::hash2curve::ExpandMsgXmd,
    ff::Field,
    group::{Curve, Group},
    multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective,
};
use subtle::{Choice, CtOption};

/// A proof of possession of the secret key
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProofOfPossessionVt(pub G2Projective);

display_one_impl!(ProofOfPossessionVt);

serde_impl!(ProofOfPossessionVt, G2Projective);

cond_select_impl!(ProofOfPossessionVt, G2Projective);

impl ProofOfPossessionVt {
    /// Number of bytes needed to represent the proof
    pub const BYTES: usize = G2Projective::COMPRESSED_BYTES;
    /// The domain separation tag
    const DST: &'static [u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// Create a new proof of possession
    pub fn new(sk: &SecretKey) -> Option<Self> {
        if sk.0.is_zero().unwrap_u8() == 1u8 {
            return None;
        }
        let pk = PublicKeyVt::from(sk);
        let a = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&pk.to_bytes(), Self::DST);
        Some(Self(a * sk.0))
    }

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);

    /// Verify if the proof is over `pk`
    pub fn verify(&self, pk: PublicKeyVt) -> Choice {
        if (self.is_invalid() | pk.is_invalid()).unwrap_u8() == 1 {
            return Choice::from(0);
        }
        let a = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&pk.to_bytes(), Self::DST);
        let g1 = -G1Affine::generator();

        multi_miller_loop(&[
            (&pk.0.to_affine(), &G2Prepared::from(a.to_affine())),
            (&g1, &G2Prepared::from(self.0.to_affine())),
        ])
        .final_exponentiation()
        .is_identity()
    }
}

#[test]
fn pop_vt_works() {
    use crate::MockRng;
    use rand_core::SeedableRng;

    let seed = [2u8; 16];
    let mut rng = MockRng::from_seed(seed);
    let sk = SecretKey::random(&mut rng);
    let pop = ProofOfPossessionVt::new(&sk).unwrap();
    let pk = PublicKeyVt::from(&sk);
    assert_eq!(pop.verify(pk).unwrap_u8(), 1);
}
