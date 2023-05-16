use bls12_381_plus::elliptic_curve::group::{Group, GroupEncoding};
use core::fmt::Display;
use subtle::ConditionallySelectable;

/// The hash to curve point methods
pub trait HashToPoint {
    /// The output point group
    type Output: Group + GroupEncoding + Default + Display + ConditionallySelectable;

    /// Compute the output from a hash method
    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output;
}
