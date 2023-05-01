use crate::partial_signature_vt::PARTIAL_SIGNATURE_VT_BYTES;
use crate::{PartialSignatureVt, PublicKeyVt, SecretKey};
use bls12_381_plus::{
    elliptic_curve::hash2curve::ExpandMsgXmd,
    ff::Field,
    group::{Curve, Group},
    multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective, Scalar,
};
use subtle::{Choice, CtOption};
use vsss_rs::{combine_shares_group_const_generics, const_generics::Share, heapless::Vec, Error};

/// Represents a BLS SignatureVt in G1 using the proof of possession scheme
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignatureVt(pub G2Projective);

display_one_impl!(SignatureVt);

serde_impl!(SignatureVt, G2Projective);

cond_select_impl!(SignatureVt, G2Projective);

impl SignatureVt {
    /// Number of bytes needed to represent the SignatureVt
    pub const BYTES: usize = G2Projective::COMPRESSED_BYTES;
    /// The domain separation tag
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// Create a new bls
    pub fn new<B: AsRef<[u8]>>(sk: &SecretKey, msg: B) -> Option<Self> {
        if sk.0.is_zero().unwrap_u8() == 1u8 {
            return None;
        }
        let a = Self::hash_msg(msg.as_ref());
        Some(Self(a * sk.0))
    }

    pub(crate) fn hash_msg(msg: &[u8]) -> G2Projective {
        G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, Self::DST)
    }

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);

    /// Verify if the bls is over `msg` with `pk`
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKeyVt, msg: B) -> Choice {
        if (pk.0.is_identity() | self.is_invalid()).unwrap_u8() == 1 {
            return 0u8.into();
        }
        let a = Self::hash_msg(msg.as_ref());
        let g1 = -G1Affine::generator();

        multi_miller_loop(&[
            (&pk.0.to_affine(), &G2Prepared::from(a.to_affine())),
            (&g1, &G2Prepared::from(self.0.to_affine())),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Combine partial signatures into a completed signature
    pub fn from_partials(partials: &[PartialSignatureVt]) -> Result<Self, Error> {
        if partials.len() < 2 {
            return Err(Error::SharingLimitLessThanThreshold);
        }
        let mut pp = Vec::<Share<PARTIAL_SIGNATURE_VT_BYTES>, 255>::new();
        for partial in partials {
            pp.push(partial.0.clone()).unwrap();
        }
        let point = combine_shares_group_const_generics::<
            Scalar,
            G2Projective,
            PARTIAL_SIGNATURE_VT_BYTES,
        >(&pp)?;
        Ok(Self(point))
    }
}

#[test]
fn signature_vt_works() {
    use crate::MockRng;
    use rand_core::{RngCore, SeedableRng};

    let seed = [2u8; 16];
    let mut rng = MockRng::from_seed(seed);
    let sk = SecretKey::random(&mut rng);
    let mut msg = [0u8; 12];
    rng.fill_bytes(&mut msg);
    let sig = SignatureVt::new(&sk, msg).unwrap();
    let pk = PublicKeyVt::from(&sk);
    assert_eq!(sig.verify(pk, msg).unwrap_u8(), 1);
}

#[test]
fn threshold_works() {
    use crate::MockRng;
    use rand_core::{RngCore, SeedableRng};

    let seed = [3u8; 16];
    let mut rng = MockRng::from_seed(seed);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKeyVt::from(&sk);

    let res_shares = sk.split(2, 3, &mut rng);
    assert!(res_shares.is_ok());
    let shares = res_shares.unwrap();
    let mut msg = [0u8; 12];
    rng.fill_bytes(&mut msg);

    let mut sigs = [
        PartialSignatureVt::default(),
        PartialSignatureVt::default(),
        PartialSignatureVt::default(),
    ];
    for (i, share) in shares.iter().enumerate() {
        let opt = PartialSignatureVt::new(share, &msg);
        assert!(opt.is_some());
        sigs[i] = opt.unwrap();
    }

    // Try all combinations to make sure they verify
    for i in 0..3 {
        for j in 0..3 {
            if i == j {
                continue;
            }
            let res = SignatureVt::from_partials(&[sigs[i].clone(), sigs[j].clone()]);
            assert!(res.is_ok());
            let sig = res.unwrap();
            assert_eq!(sig.verify(pk, msg).unwrap_u8(), 1);
        }
    }
}
