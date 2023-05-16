mod utils;
use blsful::*;
use utils::*;

#[test]
fn signatures_work() {
    for scheme in &[
        SignatureSchemes::Basic,
        SignatureSchemes::MessageAugmentation,
        SignatureSchemes::ProofOfPossession,
    ] {
        let sk1 = Bls12381G1::new_secret_key();
        let sk2 = Bls12381G2::new_secret_key();

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();

        let res1 = sk1.sign(*scheme, TEST_MSG);
        let res2 = sk2.sign(*scheme, TEST_MSG);

        assert!(res1.is_ok());
        assert!(res2.is_ok());

        let sig1 = res1.unwrap();
        let sig2 = res2.unwrap();

        assert!(sig1.verify(&pk1, TEST_MSG).is_ok());
        assert!(sig2.verify(&pk2, TEST_MSG).is_ok());
        assert!(sig1.verify(&pk1, BAD_MSG).is_err());
        assert!(sig2.verify(&pk2, BAD_MSG).is_err());
    }
}

#[test]
fn proof_of_possession_works() {
    let sk = Bls12381G1::new_secret_key();
    let pk = sk.public_key();
    let pop = sk.proof_of_possession().unwrap();
    assert!(pop.verify(pk).is_ok());

    let sk = SecretKey::<Bls12381G2>(sk.0);
    let pk = sk.public_key();
    let pop = sk.proof_of_possession().unwrap();
    assert!(pop.verify(pk).is_ok());

    let sk2 = Bls12381G2::new_secret_key();
    let pk2 = sk2.public_key();
    assert!(pop.verify(pk2).is_err());
}
