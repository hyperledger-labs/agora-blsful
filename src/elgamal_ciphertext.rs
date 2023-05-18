use crate::*;
use core::ops::{Add, AddAssign};

/// An ElGamal ciphertext
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalCiphertext<
    C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop,
> {
    /// The first component of the ciphertext
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub c1: <C as Pairing>::PublicKey,
    /// The second component of the ciphertext
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub c2: <C as Pairing>::PublicKey,
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Display
    for ElGamalCiphertext<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{{c1: {}, c2: {}}}", self.c1, self.c2)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Debug
    for ElGamalCiphertext<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "ElGamalCiphertext{{c1: {:?}, c2: {:?}}}",
            self.c1, self.c2
        )
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Copy
    for ElGamalCiphertext<C>
{
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Clone
    for ElGamalCiphertext<C>
{
    fn clone(&self) -> Self {
        Self {
            c1: self.c1,
            c2: self.c2,
        }
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    subtle::ConditionallySelectable for ElGamalCiphertext<C>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c1: <C as Pairing>::PublicKey::conditional_select(&a.c1, &b.c1, choice),
            c2: <C as Pairing>::PublicKey::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

impl<'a, 'b, C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    Add<&'b ElGamalCiphertext<C>> for &'a ElGamalCiphertext<C>
{
    type Output = ElGamalCiphertext<C>;

    fn add(self, rhs: &'b ElGamalCiphertext<C>) -> Self::Output {
        *self + *rhs
    }
}

impl<'a, C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    Add<&'a ElGamalCiphertext<C>> for ElGamalCiphertext<C>
{
    type Output = Self;

    fn add(self, rhs: &'a ElGamalCiphertext<C>) -> Self::Output {
        self + *rhs
    }
}

impl<'a, C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    Add<ElGamalCiphertext<C>> for &'a ElGamalCiphertext<C>
{
    type Output = ElGamalCiphertext<C>;

    fn add(self, rhs: ElGamalCiphertext<C>) -> Self::Output {
        *self + rhs
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    Add<ElGamalCiphertext<C>> for ElGamalCiphertext<C>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    AddAssign<ElGamalCiphertext<C>> for ElGamalCiphertext<C>
{
    fn add_assign(&mut self, rhs: ElGamalCiphertext<C>) {
        self.c1 += rhs.c1;
        self.c2 += rhs.c2;
    }
}

impl<'a, C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    AddAssign<&'a ElGamalCiphertext<C>> for ElGamalCiphertext<C>
{
    fn add_assign(&mut self, rhs: &'a ElGamalCiphertext<C>) {
        self.c1 += rhs.c1;
        self.c2 += rhs.c2;
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    ElGamalCiphertext<C>
{
    /// Decrypt this ciphertext
    pub fn decrypt(&self, sk: &SecretKey<C>) -> <C as Pairing>::PublicKey {
        <C as BlsElGamal>::decrypt(sk.0, self.c1, self.c2)
    }
}
