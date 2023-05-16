mod utils;
use blsful::*;
use utils::*;

#[test]
fn sign_crypt_works() {
    // Repeat test a few times to ensure randomness and fuzz testing
    for _ in 0..25 {
        let sk = Bls12381G1::new_secret_key();
        let pk = sk.public_key();
        let ciphertext = pk.sign_crypt(SignatureSchemes::Basic, TEST_MSG);
        assert_eq!(ciphertext.is_valid().unwrap_u8(), 1u8);
        let plaintext = ciphertext.decrypt(&sk);
        assert_eq!(plaintext.is_some().unwrap_u8(), 1u8);
        let plaintext = plaintext.unwrap();
        assert_eq!(plaintext.as_slice(), TEST_MSG);

        let sk2 = Bls12381G1::new_secret_key();
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

#[test]
fn sign_crypt_with_shares_works() {}

#[test]
fn time_lock_works() {
    let sk = Bls12381G1::new_secret_key();
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
