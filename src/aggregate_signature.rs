use crate::{PublicKey, Signature};
use bls12_381_plus::{G1Affine, G1Projective, G2Affine, group::{Group, Curve}};
use subtle::{Choice, CtOption};

/// Represents a BLS signature in G1 for multiple signatures that signed the different messages
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AggregateSignature(pub G1Projective);

display_one_impl!(AggregateSignature);

impl From<&[Signature]> for AggregateSignature {
    fn from(sigs: &[Signature]) -> Self {
        let mut g = G1Projective::IDENTITY;
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}

serde_impl!(AggregateSignature, G1Projective);

cond_select_impl!(AggregateSignature, G1Projective);

impl AggregateSignature {
    /// Number of bytes needed to represent the signature
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);

    /// Verify this multi signature is over `msg` with the multi public key
    pub fn verify<B: AsRef<[u8]>>(&self, data: &[(PublicKey, B)]) -> Choice {
        if self.is_invalid().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }

        #[cfg(not(feature = "alloc"))]
        fn core_aggregate_verify<B: AsRef<[u8]>>(
            sig: &G1Projective,
            data: &[(PublicKey, B)],
        ) -> Choice {
            use bls12_381_plus::{pairing, Gt};

            let mut res = Gt::IDENTITY;
            for (key, msg) in data {
                if key.is_invalid().unwrap_u8() == 1 {
                    return Choice::from(0u8);
                }
                let a = Signature::hash_msg(msg.as_ref());
                res += pairing(&a.to_affine(), &key.0.to_affine());
            }
            res += pairing(&sig.to_affine(), &-G2Affine::generator());
            res.is_identity()
        }
        #[cfg(any(feature = "alloc", feature = "std"))]
        fn core_aggregate_verify<B: AsRef<[u8]>>(
            sig: &G1Projective,
            data: &[(PublicKey, B)],
        ) -> Choice {
            #[cfg(all(feature = "alloc", not(feature = "std")))]
            use alloc::vec::Vec;
            use bls12_381_plus::{multi_miller_loop, G2Prepared};

            if data.iter().any(|(k, _)| k.is_invalid().unwrap_u8() == 1) {
                return Choice::from(0u8);
            }

            let mut data = data
                .iter()
                .map(|(key, m)| {
                    (
                        Signature::hash_msg(m.as_ref()).to_affine(),
                        G2Prepared::from(key.0.to_affine()),
                    )
                })
                .collect::<Vec<(G1Affine, G2Prepared)>>();

            data.push((sig.to_affine(), G2Prepared::from(-G2Affine::generator())));
            // appease borrow checker
            let t = data
                .iter()
                .map(|(p1, p2)| (p1, p2))
                .collect::<Vec<(&G1Affine, &G2Prepared)>>();
            multi_miller_loop(t.as_slice())
                .final_exponentiation()
                .is_identity()
        }
        core_aggregate_verify(&self.0, data)
    }
}
