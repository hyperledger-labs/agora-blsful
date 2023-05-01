use crate::libs::*;
use crate::*;
use bls12_381_plus::{
    ff::Field,
    group::{Curve, Group, GroupEncoding},
    multi_miller_loop, G1Affine, G1Projective, G2Prepared, G2Projective, Gt,
};
use core::marker::PhantomData;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use subtle::*;
use vsss_rs_std::{combine_shares_group, Share};

pub(crate) trait SignCrypt {
    /// The public key group
    type PublicKey: Group + GroupEncoding + Default;
    /// The signature group
    type Signature: Group<Scalar = <Self::PublicKey as Group>::Scalar> + GroupEncoding + Default;
    /// The target group from a pairing computation
    type PairingResult: Group + GroupEncoding;
    /// Compute the pairing based on supplied points
    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult;

    /// Generate a random scalar
    fn random_non_zero_scalar() -> <Self::Signature as Group>::Scalar;

    /// Create a new ciphertext
    fn seal(pk: Self::PublicKey, message: &[u8]) -> (Self::PublicKey, Vec<u8>, Self::Signature) {
        // r ← Zq
        let r = Self::random_non_zero_scalar();
        // U = P^r
        let u = Self::PublicKey::generator() * r;
        // V = HℓX(R) ⊕ M
        let overhead = uint_zigzag::Uint::from(message.len());
        let mut overhead_bytes = overhead.to_vec();
        overhead_bytes.extend_from_slice(message);
        while overhead_bytes.len() < 32 {
            overhead_bytes.push(0u8);
        }
        let v = Self::compute_v(pk * r, overhead_bytes.as_slice());
        // W = HG2(U′ || V)^r
        let w = Self::compute_w(u, v.as_slice()) * r;
        (u, v, w)
    }

    /// Check if the ciphertext is valid
    fn valid(u: Self::PublicKey, v: &[u8], w: Self::Signature) -> Choice {
        let w_tick = Self::compute_w(u, v);

        let g = -Self::PublicKey::generator();
        let pair_result = Self::pairing(&[(w, g), (w_tick, u)]);

        pair_result.is_identity() & !u.is_identity() & !w.is_identity()
    }

    /// Open a ciphertext if the secret can verify the signature
    fn unseal(
        u: Self::PublicKey,
        v: &[u8],
        w: Self::Signature,
        sk: &<Self::PublicKey as Group>::Scalar,
    ) -> CtOption<Vec<u8>> {
        let valid = Self::valid(u, v, w);
        let ua = u * ConditionallySelectable::conditional_select(
            &<Self::PublicKey as Group>::Scalar::ZERO,
            sk,
            valid,
        );
        Self::decrypt(v, ua, valid)
    }

    /// Open the ciphertext given the decryption shares.
    fn unseal_with_shares(
        u: Self::PublicKey,
        v: &[u8],
        w: Self::Signature,
        shares: &[DecryptionShare<Self::PublicKey>],
    ) -> CtOption<Vec<u8>> {
        if shares.len() < 2 {
            return CtOption::new(vec![], 0u8.into());
        }
        let ss = shares
            .iter()
            .map(|s| s.0 .0.clone())
            .collect::<Vec<Share>>();
        let ua = combine_shares_group::<<Self::PublicKey as Group>::Scalar, Self::PublicKey>(&ss)
            .ok()
            .unwrap_or_default();
        Self::decrypt(v, ua, Self::valid(u, v, w))
    }

    /// Decrypt a ciphertext
    fn decrypt(v: &[u8], ua: Self::PublicKey, valid: Choice) -> CtOption<Vec<u8>> {
        let plaintext = Self::compute_v(ua, v);
        if let Some(overhead) = uint_zigzag::Uint::peek(plaintext.as_slice()) {
            let len = uint_zigzag::Uint::try_from(&plaintext[..overhead])
                .unwrap()
                .0 as usize;
            if len < plaintext.len() - overhead {
                return CtOption::new(plaintext[overhead..overhead + len].to_vec(), valid);
            }
        }
        CtOption::new(v.to_vec(), 0u8.into())
    }

    /// Compute the `V` value
    fn compute_v(uar: Self::PublicKey, r: &[u8]) -> Vec<u8> {
        use crate::libs::*;

        let mut hasher = Shake128::default();
        hasher.update(uar.to_bytes().as_ref());
        // HℓX(R)
        let mut reader = hasher.finalize_xof();

        let mut v = vec![0u8; r.len()];
        reader.read(&mut v);
        // V = HℓX(R) ⊕ M
        byte_xor(r, &v)
    }

    /// Compute the `W` value
    fn compute_w(u: Self::PublicKey, v: &[u8]) -> Self::Signature {
        // W = HG2(U′ || V)^r
        let u_bytes = u.to_bytes();
        let mut t = Vec::with_capacity(u_bytes.as_ref().len() + v.len());
        t.extend_from_slice(&u_bytes.as_ref());
        t.extend_from_slice(v);
        Self::hash_to_group(t.as_slice())
    }

    /// Verify a decryption share using a public key share and ciphertext
    fn verify_share(
        share: Self::PublicKey,
        pk: Self::PublicKey,
        u: Self::PublicKey,
        v: &[u8],
        w: Self::Signature,
    ) -> Choice {
        let hash = -Self::compute_w(u, v);
        Self::pairing(&[(hash, share), (w, pk)]).is_identity()
    }

    /// Hash a message to the signature group
    fn hash_to_group<B: AsRef<[u8]>>(msg: B) -> Self::Signature;
}

/// Ciphertext generated according to section C in
/// <https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf>
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Ciphertext<U: Group + GroupEncoding + Default, W: Group + GroupEncoding + Default> {
    /// U value
    pub u: U,
    /// V value
    pub v: Vec<u8>,
    /// W value
    pub w: W,
}

impl Ciphertext<G1Projective, G2Projective> {
    /// Test if the ciphertext is valid
    pub fn is_valid(&self) -> Choice {
        SignCryptorG1::valid(self.u, self.v.as_slice(), self.w)
    }

    /// Decrypt the ciphertext if its valid from a secret key
    pub fn decrypt(&self, sk: &SecretKey) -> CtOption<Vec<u8>> {
        SignCryptorG1::unseal(self.u, self.v.as_slice(), self.w, &sk.0)
    }

    /// Decrypt the ciphertext if its valid from secret key shares
    pub fn decrypt_with_shares<B: AsRef<[DecryptionShare<G1Projective>]>>(
        &self,
        shares: B,
    ) -> CtOption<Vec<u8>> {
        SignCryptorG1::unseal_with_shares(self.u, self.v.as_slice(), self.w, shares.as_ref())
    }

    /// Create a decryption share
    pub fn create_decryption_share(
        &self,
        secret_key_share: &SecretKeyShare,
    ) -> Option<DecryptionShare<G1Projective>> {
        let value = self.u * secret_key_share.0.as_field_element::<Scalar>().ok()?;
        let mut share = Vec::with_capacity(G1Projective::COMPRESSED_BYTES + 1);
        share.push(secret_key_share.0.identifier());
        share.extend_from_slice(value.to_bytes().as_ref());
        Some(DecryptionShare((Share(share), PhantomData)))
    }
}

impl Ciphertext<G2Projective, G1Projective> {
    /// Test if the ciphertext is valid
    pub fn is_valid(&self) -> Choice {
        SignCryptorG2::valid(self.u, self.v.as_slice(), self.w)
    }

    /// Decrypt the ciphertext if its valid from a secret key
    pub fn decrypt(&self, sk: &SecretKey) -> CtOption<Vec<u8>> {
        SignCryptorG2::unseal(self.u, self.v.as_slice(), self.w, &sk.0)
    }

    /// Decrypt the ciphertext if its valid from secret key shares
    pub fn decrypt_with_shares<B: AsRef<[DecryptionShare<G2Projective>]>>(
        &self,
        shares: B,
    ) -> CtOption<Vec<u8>> {
        SignCryptorG2::unseal_with_shares(self.u, self.v.as_slice(), self.w, shares.as_ref())
    }
}

/// A decryption Share
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct DecryptionShare<G: Group + GroupEncoding + Default>(pub (Share, PhantomData<G>));

pub(crate) struct SignCryptorG1;
pub(crate) struct SignCryptorG2;

impl SignCrypt for SignCryptorG1 {
    type PublicKey = G1Projective;
    type Signature = G2Projective;
    type PairingResult = Gt;

    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult {
        let t = points
            .iter()
            .map(|(p1, p2)| (p2.to_affine(), G2Prepared::from(p1.to_affine())))
            .collect::<Vec<(G1Affine, G2Prepared)>>();
        let ref_t = t
            .iter()
            .map(|(p1, p2)| (p1, p2))
            .collect::<Vec<(&G1Affine, &G2Prepared)>>();
        multi_miller_loop(ref_t.as_slice()).final_exponentiation()
    }

    fn random_non_zero_scalar() -> Scalar {
        const SALT: &'static [u8] = b"SIGNCRYPT_BLS12381G1_XOF:SHA3-256_";
        random_nz_fr(Some(SALT), get_crypto_rng())
    }

    fn hash_to_group<B: AsRef<[u8]>>(msg: B) -> Self::Signature {
        SignatureVt::hash_msg(msg.as_ref())
    }
}

impl SignCrypt for SignCryptorG2 {
    type PublicKey = G2Projective;
    type Signature = G1Projective;
    type PairingResult = Gt;

    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult {
        let t = points
            .iter()
            .map(|(p1, p2)| (p1.to_affine(), G2Prepared::from(p2.to_affine())))
            .collect::<Vec<(G1Affine, G2Prepared)>>();
        let ref_t = t
            .iter()
            .map(|(p1, p2)| (p1, p2))
            .collect::<Vec<(&G1Affine, &G2Prepared)>>();
        multi_miller_loop(ref_t.as_slice()).final_exponentiation()
    }

    fn random_non_zero_scalar() -> Scalar {
        const SALT: &'static [u8] = b"SIGNCRYPT_BLS12381G2_XOF:SHA3-256_";
        random_nz_fr(Some(SALT), get_crypto_rng())
    }

    fn hash_to_group<B: AsRef<[u8]>>(msg: B) -> Self::Signature {
        Signature::hash_msg(msg.as_ref())
    }
}

#[test]
fn signcryption_works() {
    let sk = SecretKey::hash(b"signcryption_works");
    let pk = PublicKey::from(&sk);

    let msg = b"this is an encrypted message";
    let mut ciphertext = pk.sign_crypt(msg);
    assert_eq!(ciphertext.is_valid().unwrap_u8(), 1u8);
    let res = ciphertext.decrypt(&sk);
    assert_eq!(res.is_some().unwrap_u8(), 1u8);
    assert_eq!(res.unwrap().as_slice(), msg);
    ciphertext.u = G2Projective::IDENTITY;
    assert_eq!(ciphertext.is_valid().unwrap_u8(), 0u8);
    let res = ciphertext.decrypt(&sk);
    assert_eq!(res.is_none().unwrap_u8(), 1u8);
}

#[test]
fn signcryption_threshold_works() {
    let sk = SecretKey::hash(b"signcryption_threshold_works");
    let pk = PublicKey::from(&sk);

    let msg = b"this is an encrypted message";
    let ciphertext = pk.sign_crypt(msg);
    assert_eq!(ciphertext.is_valid().unwrap_u8(), 1u8);

    let mut rng = get_crypto_rng();
    let mut shares = vsss_rs_std::shamir::split_secret(3, 5, sk.0, &mut rng).unwrap();
    shares.iter_mut().for_each(|s| {
        let pt = ciphertext.u * s.as_field_element::<Scalar>().unwrap();
        s.0.resize(97, 0u8);
        s.0[1..].copy_from_slice(pt.to_bytes().as_ref());
    });
    let shares: Vec<_> = shares
        .iter()
        .map(|s| DecryptionShare((s.clone(), PhantomData)))
        .collect();

    let res = ciphertext.decrypt_with_shares(&shares[2..]);
    assert_eq!(res.is_some().unwrap_u8(), 1u8);
    assert_eq!(res.unwrap().as_slice(), msg);
    let res = ciphertext.decrypt_with_shares(&shares[3..]);
    assert_eq!(res.is_none().unwrap_u8(), 1u8);
    let res = ciphertext.decrypt_with_shares(&shares[4..]);
    assert_eq!(res.is_none().unwrap_u8(), 1u8);
}

#[test]
fn decryption_share_verify_works() {
    let sk = SecretKey::hash(b"decryption_share_verify_works");
    let pk = PublicKey::from(&sk);

    let msg = b"this is an encrypted message";
    let ciphertext = pk.sign_crypt(msg);
    assert_eq!(ciphertext.is_valid().unwrap_u8(), 1u8);

    let mut rng = get_crypto_rng();
    let shares = vsss_rs_std::shamir::split_secret(3, 5, sk.0, &mut rng).unwrap();
    let decryption_shares: Vec<Share> = shares
        .iter()
        .map(|s| {
            let pt = ciphertext.u * s.as_field_element::<Scalar>().unwrap();
            let mut v = s.clone();
            v.0.resize(97, 0u8);
            v.0[1..].copy_from_slice(pt.to_bytes().as_ref());
            v
        })
        .collect();
    let decryption_shares: Vec<DecryptionShare<G2Projective>> = decryption_shares
        .iter()
        .map(|s| DecryptionShare((s.clone(), PhantomData)))
        .collect();

    for (dsh, s) in decryption_shares.iter().zip(shares.iter()) {
        let pk_share = G2Projective::GENERATOR * s.as_field_element::<Scalar>().unwrap();
        assert_eq!(
            SignCryptorG2::verify_share(
                dsh.0 .0.as_group_element().unwrap(),
                pk_share,
                ciphertext.u,
                ciphertext.v.as_slice(),
                ciphertext.w
            )
            .unwrap_u8(),
            1u8
        );
    }
}
