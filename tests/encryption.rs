mod utils;
use blsful::*;
use utils::*;
use rstest::*;

#[rstest]
#[case::g1(Bls12381G1)]
#[case::g2(Bls12381G2)]
fn sign_crypt_works<C: BlsSignatureBasic
+ BlsSignatureMessageAugmentation
+ BlsSignaturePop
+ BlsSignCrypt
+ BlsTimeCrypt
+ BlsSignatureProof
+ BlsSerde
+ PartialEq
+ Eq
+ std::fmt::Debug>(#[case] _c: C) {
    // Repeat test a few times to ensure randomness and fuzz testing
    for _ in 0..25 {
        let sk = SecretKey::<C>::new();
        let pk = sk.public_key();
        let ciphertext = pk.sign_crypt(SignatureSchemes::Basic, TEST_MSG);
        assert_eq!(ciphertext.is_valid().unwrap_u8(), 1u8);
        let plaintext = ciphertext.decrypt(&sk);
        assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
        let plaintext = plaintext.unwrap();
        assert_eq!(plaintext.as_slice(), TEST_MSG);

        let sk2 = SecretKey::<C>::new();
        assert_ne!(sk, sk2);
        let plaintext = ciphertext.decrypt(&sk2);
        // Sometimes this can happen but the ciphertext should still fail
        if plaintext.is_some().into() {
            let plaintext = plaintext.unwrap();
            assert_ne!(plaintext, TEST_MSG);
        } else {
            assert_eq!(plaintext.is_none().unwrap_u8(), 1u8);
        }
    }
}

#[rstest]
#[case::g1(Bls12381G1)]
#[case::g2(Bls12381G2)]
fn sign_crypt_with_shares_works<C: BlsSignatureBasic
+ BlsSignatureMessageAugmentation
+ BlsSignaturePop
+ BlsSignCrypt
+ BlsTimeCrypt
+ BlsSignatureProof
+ BlsSerde>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();
    let shares = sk.split(2, 3).unwrap();
    let ciphertext = pk.sign_crypt(SignatureSchemes::Basic, TEST_MSG);
    let public_key_shares = shares.iter().map(|s| s.public_key().unwrap()).collect::<Vec<_>>();
    let decryption_shares = shares.iter().map(|s| ciphertext.create_decryption_share(s).unwrap()).collect::<Vec<_>>();
    assert!(decryption_shares.iter().zip(public_key_shares.iter()).all(|(d, p)| d.verify(p, &ciphertext).is_ok()));

    let res = ciphertext.decrypt_with_shares(&decryption_shares);
    assert_eq!(res.is_some().unwrap_u8(), 1u8);
    let plaintext = res.unwrap();
    assert_eq!(plaintext.as_slice(), TEST_MSG);
    let res = ciphertext.decrypt_with_shares(&decryption_shares[2..]);
    assert_eq!(res.is_some().unwrap_u8(), 0u8);
}

#[rstest]
#[case::g1(Bls12381G1)]
#[case::g2(Bls12381G2)]
fn time_lock_works<C: BlsSignatureBasic
+ BlsSignatureMessageAugmentation
+ BlsSignaturePop
+ BlsSignCrypt
+ BlsTimeCrypt
+ BlsSignatureProof
+ BlsSerde>(#[case] _c: C) {
    let sk = SecretKey::<C>::new();
    let pk = sk.public_key();
    let ciphertext = pk
        .time_lock_encrypt(SignatureSchemes::Basic, TEST_MSG, TEST_ID)
        .unwrap();
    let sig = sk.sign(SignatureSchemes::Basic, TEST_ID).unwrap();
    let bad_sig = sk.sign(SignatureSchemes::Basic, BAD_MSG).unwrap();
    let bad_scheme = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_ID)
        .unwrap();

    let plaintext = ciphertext.decrypt(&sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
    let plaintext = plaintext.unwrap();
    assert_eq!(plaintext.as_slice(), TEST_MSG);

    let plaintext = ciphertext.decrypt(&bad_sig);
    assert_eq!(plaintext.is_some().unwrap_u8(), 0u8);
    let plaintext = ciphertext.decrypt(&bad_scheme);
    assert_eq!(plaintext.is_some().unwrap_u8(), 0u8);
}
