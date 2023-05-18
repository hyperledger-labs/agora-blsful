mod utils;
use blsful::*;
use utils::*;
use rstest::*;

#[rstest]
#[case::g1(Bls12381G1)]
#[case::g2(Bls12381G2)]
fn basic_types_serialize_json<C: BlsSignatureBasic
+ BlsSignatureMessageAugmentation
+ BlsSignaturePop
+ BlsSignCrypt
+ BlsTimeCrypt
+ BlsSignatureProof
+ BlsSerde
+ PartialEq
+ Eq
+ std::fmt::Debug>(#[case] _c: C) {
    let sk = SecretKey::<C>::random(MockRng::default());
    let pk = sk.public_key();
    let sig_b = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig_ma = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let sig_pop = sk.sign(SignatureSchemes::ProofOfPossession, TEST_MSG).unwrap();

    let res = serde_json::to_vec(&sk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<SecretKey<C>>(&text);
    assert!(res.is_ok());
    let sk2 = res.unwrap();
    assert_eq!(sk, sk2);

    let res = serde_json::to_vec(&pk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<PublicKey<C>>(&text);
    assert!(res.is_ok());
    let pk2 = res.unwrap();
    assert_eq!(pk, pk2);

    let res = serde_json::to_vec(&sig_b);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_b2 = res.unwrap();
    assert_eq!(sig_b, sig_b2);

    let res = serde_json::to_vec(&sig_ma);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_ma2 = res.unwrap();
    assert_eq!(sig_ma, sig_ma2);

    let res = serde_json::to_vec(&sig_pop);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_json::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_pop2 = res.unwrap();
    assert_eq!(sig_pop, sig_pop2);
}

#[rstest]
#[case::g1(Bls12381G1)]
#[case::g2(Bls12381G2)]
fn basic_types_serialize_binary<C: BlsSignatureBasic
+ BlsSignatureMessageAugmentation
+ BlsSignaturePop
+ BlsSignCrypt
+ BlsTimeCrypt
+ BlsSignatureProof
+ BlsSerde
+ PartialEq
+ Eq
+ std::fmt::Debug>(#[case] _c: C) {
    let sk = SecretKey::<C>::random(MockRng::default());
    let pk = sk.public_key();
    let sig_b = sk.sign(SignatureSchemes::Basic, TEST_MSG).unwrap();
    let sig_ma = sk
        .sign(SignatureSchemes::MessageAugmentation, TEST_MSG)
        .unwrap();
    let sig_pop = sk.sign(SignatureSchemes::ProofOfPossession, TEST_MSG).unwrap();

    let res = serde_bare::to_vec(&sk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<SecretKey<C>>(&text);
    assert!(res.is_ok());
    let sk2 = res.unwrap();
    assert_eq!(sk, sk2);

    let res = serde_bare::to_vec(&pk);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<PublicKey<C>>(&text);
    assert!(res.is_ok());
    let pk2 = res.unwrap();
    assert_eq!(pk, pk2);

    let res = serde_bare::to_vec(&sig_b);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_b2 = res.unwrap();
    assert_eq!(sig_b, sig_b2);

    let res = serde_bare::to_vec(&sig_ma);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_ma2 = res.unwrap();
    assert_eq!(sig_ma, sig_ma2);

    let res = serde_bare::to_vec(&sig_pop);
    assert!(res.is_ok());
    let text = res.unwrap();
    let res = serde_bare::from_slice::<Signature<C>>(&text);
    assert!(res.is_ok());
    let sig_pop2 = res.unwrap();
    assert_eq!(sig_pop, sig_pop2);
}

#[rstest]
#[case::g1(Bls12381G1)]
#[case::g2(Bls12381G2)]
fn shares_serialize_json<C: BlsSignatureBasic
+ BlsSignatureMessageAugmentation
+ BlsSignaturePop
+ BlsSignCrypt
+ BlsTimeCrypt
+ BlsSignatureProof
+ BlsSerde
+ PartialEq
+ Eq
+ std::fmt::Debug
+ serde::Serialize
+ serde::de::DeserializeOwned>(#[case] _c: C) {
    let sk = SecretKey::<C>::from_hash(b"shares_serialize_json");
    // High number to test for fuzzing
    let sk_shares = sk.split(10, 20).unwrap();
    for share in &sk_shares {
        let res = serde_json::to_vec(&share);
        assert!(res.is_ok());
        let text = res.unwrap();
        let res = serde_json::from_slice::<SecretKeyShare<C>>(&text);
        assert!(res.is_ok());
        let share2 = res.unwrap();
        assert_eq!(share, &share2);

        let pks = share.public_key().unwrap();
        let res = serde_json::to_vec(&pks);
        assert!(res.is_ok());
        let text = res.unwrap();
        let res = serde_json::from_slice::<PublicKeyShare<C>>(&text);
        assert!(res.is_ok());
        let pks2 = res.unwrap();
        assert_eq!(pks, pks2);

        let sgs = share.sign(SignatureSchemes::ProofOfPossession, TEST_MSG).unwrap();
        let res = serde_json::to_vec(&sgs);
        assert!(res.is_ok());
        let text = res.unwrap();
        let res = serde_json::from_slice::<SignatureShare<C>>(&text);
        assert!(res.is_ok());
        let sgs2 = res.unwrap();
        assert_eq!(sgs, sgs2);
    }
}