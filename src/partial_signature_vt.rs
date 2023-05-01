use crate::{SecretKeyShare, SignatureVt};
use bls12_381_plus::{group::Curve, G2Affine, G2Projective, Scalar};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::Choice;
use vsss_rs::{const_generics::Share, heapless::Vec};

/// Represents a BLS partial signature in G2 using the proof of possession scheme
#[derive(Clone, Debug, Default)]
pub struct PartialSignatureVt(pub Share<PARTIAL_SIGNATURE_VT_BYTES>);

display_size_impl!(PartialSignatureVt, PARTIAL_SIGNATURE_VT_BYTES);

impl From<Share<PARTIAL_SIGNATURE_VT_BYTES>> for PartialSignatureVt {
    fn from(share: Share<PARTIAL_SIGNATURE_VT_BYTES>) -> Self {
        Self(share)
    }
}

impl<'a> From<&'a Share<PARTIAL_SIGNATURE_VT_BYTES>> for PartialSignatureVt {
    fn from(share: &'a Share<PARTIAL_SIGNATURE_VT_BYTES>) -> Self {
        Self(share.clone())
    }
}

impl Serialize for PartialSignatureVt {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(s)
    }
}

impl<'de> Deserialize<'de> for PartialSignatureVt {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = Share::<PARTIAL_SIGNATURE_VT_BYTES>::deserialize(d)?;
        Ok(Self(p))
    }
}

impl PartialSignatureVt {
    /// Number of bytes needed to represent the signature
    pub const BYTES: usize = PARTIAL_SIGNATURE_VT_BYTES;

    /// Create a new bls
    pub fn new<B: AsRef<[u8]>>(sk: &SecretKeyShare, msg: B) -> Option<Self> {
        if sk.is_zero() {
            return None;
        }
        let a = SignatureVt::hash_msg(msg.as_ref());
        let t = <[u8; 32]>::try_from(sk.0.value()).unwrap();
        let res = Scalar::from_bytes(&t).map(|s| {
            let point = a * s;
            let mut bytes = Vec::<u8, PARTIAL_SIGNATURE_VT_BYTES>::new();
            bytes.push(sk.0.identifier()).unwrap();
            bytes
                .extend_from_slice(&point.to_affine().to_compressed())
                .unwrap();
            Some(PartialSignatureVt(Share(bytes)))
        });
        if res.is_some().unwrap_u8() == 1 {
            res.unwrap()
        } else {
            None
        }
    }

    /// Check if this partial signature is valid
    pub fn is_valid(&self) -> Choice {
        let t: [u8; 96] = <[u8; 96]>::try_from(self.0.value()).unwrap();
        let p = G2Affine::from_compressed(&t).map(G2Projective::from);
        p.map(|v| !v.is_identity() | v.is_on_curve())
            .unwrap_or_else(|| Choice::from(0u8))
    }

    /// Check if this partial signature is invalid
    pub fn is_invalid(&self) -> Choice {
        let t: [u8; 96] = <[u8; 96]>::try_from(self.0.value()).unwrap();
        let p = G2Affine::from_compressed(&t).map(G2Projective::from);
        p.map(|v| v.is_identity() | !v.is_on_curve())
            .unwrap_or_else(|| Choice::from(0u8))
    }

    /// Get the byte sequence that represents this partial signature
    pub fn to_bytes(self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out.copy_from_slice(self.0 .0.as_slice());
        out
    }

    /// Convert a big-endian representation of the partial signature
    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> Self {
        let mut inner = Vec::new();
        inner.extend_from_slice(bytes).unwrap();
        Self(Share(inner))
    }
}

pub(crate) const PARTIAL_SIGNATURE_VT_BYTES: usize = G2Projective::COMPRESSED_BYTES + 1;
