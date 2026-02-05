#[cfg(feature = "bn254")]
mod bn254_tests {
    use crate::{bn254, parse_field_str_inner, parse_field_str_inner_unsigned};
    use ark_ff::{AdditiveGroup, Field, One, PrimeField, UniformRand};
    use num_bigint::BigUint;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        zero: ark_bn254::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        zero_signed: ark_bn254::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fr: ark_bn254::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        fr_signed: ark_bn254::Fr,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fr_seq: Vec<ark_bn254::Fr>,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq_signed")]
        fr_seq_signed: Vec<ark_bn254::Fr>,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fq: ark_bn254::Fq,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fq_seq: Vec<ark_bn254::Fq>,
        #[serde(serialize_with = "bn254::serialize_g1")]
        #[serde(deserialize_with = "bn254::deserialize_g1")]
        g1: ark_bn254::G1Affine,
        #[serde(serialize_with = "bn254::serialize_g1_seq")]
        #[serde(deserialize_with = "bn254::deserialize_g1_seq")]
        g1_seq: Vec<ark_bn254::G1Affine>,
        #[serde(serialize_with = "bn254::serialize_g2")]
        #[serde(deserialize_with = "bn254::deserialize_g2")]
        g2: ark_bn254::G2Affine,
        #[serde(serialize_with = "bn254::serialize_gt")]
        #[serde(deserialize_with = "bn254::deserialize_gt")]
        gt: ark_bn254::Fq12,
    }

    impl Serializable {
        fn rand<R: Rng>(r: &mut R) -> Self {
            Self {
                zero: ark_bn254::Fr::ZERO,
                zero_signed: ark_bn254::Fr::ZERO,
                fr: r.r#gen(),
                fr_signed: r.r#gen(),
                fr_seq: (0..10).map(|_| r.r#gen::<ark_bn254::Fr>()).collect(),
                fr_seq_signed: (0..10).map(|_| r.r#gen()).collect(),
                fq: r.r#gen(),
                fq_seq: (0..10).map(|_| r.r#gen()).collect(),
                g1: r.r#gen(),
                g1_seq: (0..10).map(|_| r.r#gen()).collect(),
                g2: r.r#gen(),
                gt: r.r#gen(),
            }
        }
    }

    #[test]
    fn test_human_and_non_human_readable() {
        let mut rng = rand::thread_rng();
        let should = Serializable::rand(&mut rng);
        let json_encoded = serde_json::to_vec(&should).expect("can serialize json");
        let json =
            serde_json::from_slice::<Serializable>(&json_encoded).expect("can deserialize json");

        let mut b = Vec::new();
        ciborium::into_writer(&should, &mut b).expect("can cbor serialize");
        let ciborium: Serializable =
            ciborium::from_reader(b.as_slice()).expect("can deserialize cbor");
        assert_eq!(should, json);
        assert_eq!(should, ciborium);
    }

    #[test]
    fn test_unsigned_malleability() {
        let random_number: BigUint = ark_bn254::Fr::rand(&mut rand::thread_rng())
            .into_bigint()
            .into();
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let serialized = (random_number + modulus).to_str_radix(10);
        let is_parse_inner_true_error = parse_field_str_inner::<true, ark_bn254::Fr>(&serialized)
            .expect_err("should fail")
            .0;
        let is_parse_inner_false_error = parse_field_str_inner::<false, ark_bn254::Fr>(&serialized)
            .expect_err("should fail")
            .0;
        let is_parse_inner_unsigned_error =
            parse_field_str_inner_unsigned::<ark_bn254::Fr>(&serialized)
                .expect_err("should fail")
                .0;

        assert_eq!(is_parse_inner_true_error, "doesn't fit into field");
        assert_eq!(is_parse_inner_false_error, "doesn't fit into field");
        assert_eq!(is_parse_inner_unsigned_error, "doesn't fit into field");
    }

    #[test]
    fn test_signed_malleability() {
        let random_number: BigUint = ark_bn254::Fr::rand(&mut rand::thread_rng())
            .into_bigint()
            .into();
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let serialized = (random_number + modulus).to_str_radix(10);
        let neg_string = format!("-{serialized}");
        let is_parse_inner_true_error = parse_field_str_inner::<true, ark_bn254::Fr>(&neg_string)
            .expect_err("should fail")
            .0;
        let is_parse_inner_false_error = parse_field_str_inner::<false, ark_bn254::Fr>(&neg_string)
            .expect_err("should fail")
            .0;
        let is_parse_inner_unsigned_error =
            parse_field_str_inner_unsigned::<ark_bn254::Fr>(&neg_string)
                .expect_err("should fail")
                .0;

        assert_eq!(is_parse_inner_true_error, "only expects positive numbers");
        assert_eq!(is_parse_inner_false_error, "doesn't fit into field");
        assert_eq!(
            is_parse_inner_unsigned_error,
            "only expects positive numbers"
        );
    }

    #[test]
    fn test_signed_parsing() {
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let one = BigUint::one();
        let neg_one = format!("-{}", modulus - one);
        let field_one = parse_field_str_inner::<false, ark_bn254::Fr>("1").expect("Works");
        let field_neg_one = parse_field_str_inner::<false, ark_bn254::Fr>(&neg_one).expect("Works");
        assert_eq!(field_one, field_neg_one);

        let is_inner_unsigned_msg = parse_field_str_inner_unsigned::<ark_bn254::Fr>(&neg_one)
            .expect_err("Should fail")
            .0;
        let is_inner_true_msg = parse_field_str_inner::<true, ark_bn254::Fr>(&neg_one)
            .expect_err("Should fail")
            .0;
        assert_eq!(is_inner_unsigned_msg, "only expects positive numbers");
        assert_eq!(is_inner_true_msg, "only expects positive numbers");
        let field_zero = parse_field_str_inner::<false, ark_bn254::Fr>("0").expect("Works");
        let field_neg_zero_msg = parse_field_str_inner::<false, ark_bn254::Fr>("-0")
            .expect_err("Should fail")
            .0;
        assert_eq!(field_neg_zero_msg, "zero must be serialized as '0'");

        let parse_null_inner_unsigned_msg = parse_field_str_inner_unsigned::<ark_bn254::Fr>("-0")
            .expect_err("Should fail")
            .0;
        assert_eq!(
            parse_null_inner_unsigned_msg,
            "only expects positive numbers"
        );
        let parse_null_unsigned_msg = parse_field_str_inner::<true, ark_bn254::Fr>("-0")
            .expect_err("Should fail")
            .0;
        assert_eq!(parse_null_unsigned_msg, "only expects positive numbers");
        assert_eq!(field_zero, ark_bn254::Fr::ZERO);
    }

    #[test]
    fn test_unsigned_parsing_edge_cases() {
        #[derive(Deserialize, Debug)]
        struct UnsignedWrapper {
            #[serde(deserialize_with = "crate::deserialize_f")]
            inner: ark_bn254::Fr,
        }

        // Case 1: 0
        let json = r#"{"inner": "0"}"#;
        let res: UnsignedWrapper = serde_json::from_str(json).expect("Should parse 0");
        assert_eq!(res.inner, ark_bn254::Fr::ZERO);

        // Case 2: Negative number (should fail for unsigned)
        let json = r#"{"inner": "-1"}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects positive numbers")
        );

        // Case 3: Modulus (should fail)
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let modulus_str = modulus.to_string();
        let json = format!(r#"{{"inner": "{}"}}"#, modulus_str);
        let res = serde_json::from_str::<UnsignedWrapper>(&json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("doesn't fit into field")
        );

        // Case 4: Modulus + 1 (should fail)
        let modulus_plus_one = &modulus + BigUint::one();
        let json = format!(r#"{{"inner": "{}"}}"#, modulus_plus_one);
        let res = serde_json::from_str::<UnsignedWrapper>(&json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("doesn't fit into field")
        );

        // Case 5: Modulus - 1 (should work)
        let modulus_minus_one = &modulus - BigUint::one();
        let json = format!(r#"{{"inner": "{}"}}"#, modulus_minus_one);
        let res: UnsignedWrapper = serde_json::from_str(&json).expect("Should parse modulus - 1");
        assert_eq!(res.inner, -ark_bn254::Fr::ONE);

        // Case 6: JSON Number (not string)
        // Since deserialize_f calls deserialize_str, serde_json will expect a string token.
        // Providing a number token will cause a type mismatch error in serde_json.
        let json = r#"{"inner": 0}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is a type error
        assert!(res.unwrap_err().to_string().contains("expected a string"));

        // Case 7: Hex string
        // BigInt::from_str is base 10.
        let json = r#"{"inner": "0x123"}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is an invalid data error (parsing failed)
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 8: zero-prefixed number
        let json = r#"{"inner": "0123"}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is an invalid leading zeros error (parsing failed)
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("invalid leading zeros")
        );

        // Case 9: plus-prefixed number
        let json = r#"{"inner": "+123"}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is an invalid sign error (parsing failed)
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 10: space-prefixed number
        let json = r#"{"inner": " 123"}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is an invalid data error (parsing failed)
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 11: space-postfixed number
        let json = r#"{"inner": "123 "}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is an invalid data error (parsing failed)
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 11: zero-prefixed zero
        let json = r#"{"inner": "00"}"#;
        let res = serde_json::from_str::<UnsignedWrapper>(json);
        assert!(res.is_err());
        // verify it is an invalid data error (parsing failed)
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("zero must be serialized as '0'")
        );
    }

    #[test]
    fn test_signed_parsing_edge_cases() {
        #[derive(Deserialize, Debug)]
        struct SignedWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_signed")]
            inner: ark_bn254::Fr,
        }

        // Case 1: 0
        let json = r#"{"inner": "0"}"#;
        let res: SignedWrapper = serde_json::from_str(json).expect("Should parse 0");
        assert_eq!(res.inner, ark_bn254::Fr::ZERO);

        // Case 2: -0
        let json = r#"{"inner": "-0"}"#;
        let res = serde_json::from_str::<SignedWrapper>(json).expect_err("should fail");
        assert!(res.to_string().contains("zero must be serialized as '0'"));

        // Case 3: -1
        let json = r#"{"inner": "-1"}"#;
        let res: SignedWrapper = serde_json::from_str(json).expect("Should parse -1");
        assert_eq!(res.inner, -ark_bn254::Fr::ONE);

        // Case 4: Modulus (should fail)
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let modulus_str = modulus.to_string();
        let json = format!(r#"{{"inner": "{}"}}"#, modulus_str);
        let res = serde_json::from_str::<SignedWrapper>(&json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("doesn't fit into field")
        );

        // Case 5: Modulus + 1 (should fail)
        let modulus_plus_one = modulus + BigUint::one();
        let json = format!(r#"{{"inner": "{}"}}"#, modulus_plus_one);
        let res = serde_json::from_str::<SignedWrapper>(&json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("doesn't fit into field")
        );

        // Case 6: -Modulus (should be 0)
        let json = format!(r#"{{"inner": "-{}"}}"#, modulus_str);
        let res: SignedWrapper = serde_json::from_str(&json).expect("Should parse -Modulus");
        assert_eq!(res.inner, ark_bn254::Fr::ZERO);

        // Case 7: -(Modulus + 1) (should fail)
        let json = format!(r#"{{"inner": "-{}"}}"#, modulus_plus_one);
        let res = serde_json::from_str::<SignedWrapper>(&json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("doesn't fit into field")
        );

        // Case 8: JSON Number (not string)
        let json = r#"{"inner": 0}"#;
        let res = serde_json::from_str::<SignedWrapper>(json);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("expected a string"));

        // Case 9: Hex string
        let json = r#"{"inner": "0x123"}"#;
        let res = serde_json::from_str::<SignedWrapper>(json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 10: negative Hex string
        let json = r#"{"inner": "-0x123"}"#;
        let res = serde_json::from_str::<SignedWrapper>(json);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("only expects digits 0-9 for numbers")
        );
    }
}

#[cfg(feature = "bls12-381")]
mod bls12_381_tests {
    use crate::bls12_381;
    use ark_ec::AdditiveGroup;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        zero: ark_bls12_381::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        zero_signed: ark_bls12_381::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fr: ark_bls12_381::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        fr_signed: ark_bls12_381::Fr,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fr_seq: Vec<ark_bls12_381::Fr>,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq_signed")]
        fr_seq_signed: Vec<ark_bls12_381::Fr>,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fq: ark_bls12_381::Fq,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fq_seq: Vec<ark_bls12_381::Fq>,
        #[serde(serialize_with = "bls12_381::serialize_g1")]
        #[serde(deserialize_with = "bls12_381::deserialize_g1")]
        g1: ark_bls12_381::G1Affine,
        #[serde(serialize_with = "bls12_381::serialize_g1_seq")]
        #[serde(deserialize_with = "bls12_381::deserialize_g1_seq")]
        g1_seq: Vec<ark_bls12_381::G1Affine>,
        #[serde(serialize_with = "bls12_381::serialize_g2")]
        #[serde(deserialize_with = "bls12_381::deserialize_g2")]
        g2: ark_bls12_381::G2Affine,
        #[serde(serialize_with = "bls12_381::serialize_gt")]
        #[serde(deserialize_with = "bls12_381::deserialize_gt")]
        gt: ark_bls12_381::Fq12,
    }

    impl Serializable {
        fn rand<R: Rng>(r: &mut R) -> Self {
            Self {
                zero: ark_bls12_381::Fr::ZERO,
                zero_signed: ark_bls12_381::Fr::ZERO,
                fr: r.r#gen(),
                fr_signed: r.r#gen(),
                fr_seq: (0..10).map(|_| r.r#gen()).collect(),
                fr_seq_signed: (0..10).map(|_| r.r#gen()).collect(),
                fq: r.r#gen(),
                fq_seq: (0..10).map(|_| r.r#gen()).collect(),
                g1: r.r#gen(),
                g1_seq: (0..10).map(|_| r.r#gen()).collect(),
                g2: r.r#gen(),
                gt: r.r#gen(),
            }
        }
    }

    #[test]
    fn test_human_and_non_human_readable() {
        let mut rng = rand::thread_rng();
        let should = Serializable::rand(&mut rng);
        let json_encoded = serde_json::to_vec(&should).expect("can serialize json");
        let json =
            serde_json::from_slice::<Serializable>(&json_encoded).expect("can deserialize json");

        let mut b = Vec::new();
        ciborium::into_writer(&should, &mut b).expect("can cbor serialize");
        let ciborium: Serializable =
            ciborium::from_reader(b.as_slice()).expect("can deserialize cbor");

        assert_eq!(should, ciborium);
        assert_eq!(should, json);
    }
}

#[cfg(feature = "babyjubjub")]
mod babyjubjub_test {
    use crate::babyjubjub;
    use ark_ec::AdditiveGroup;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        zero: ark_babyjubjub::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        zero_signed: ark_babyjubjub::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fr: ark_babyjubjub::Fr,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f_signed")]
        fr_signed: ark_babyjubjub::Fr,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fr_seq: Vec<ark_babyjubjub::Fr>,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq_signed")]
        fr_seq_signed: Vec<ark_babyjubjub::Fr>,
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fq: ark_babyjubjub::Fq,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fq_seq: Vec<ark_babyjubjub::Fq>,
        #[serde(serialize_with = "babyjubjub::serialize_affine")]
        #[serde(deserialize_with = "babyjubjub::deserialize_affine")]
        affine: ark_babyjubjub::EdwardsAffine,
        #[serde(serialize_with = "babyjubjub::serialize_affine_seq")]
        #[serde(deserialize_with = "babyjubjub::deserialize_affine_seq")]
        affine_seq: Vec<ark_babyjubjub::EdwardsAffine>,
        #[serde(serialize_with = "babyjubjub::serialize_affine_seq")]
        #[serde(deserialize_with = "babyjubjub::deserialize_affine_array")]
        g2: [ark_babyjubjub::EdwardsAffine; 10],
    }

    impl Serializable {
        fn rand<R: Rng>(r: &mut R) -> Self {
            Self {
                zero: ark_babyjubjub::Fr::ZERO,
                zero_signed: ark_babyjubjub::Fr::ZERO,
                fr: r.r#gen(),
                fr_signed: r.r#gen(),
                fr_seq: (0..10).map(|_| r.r#gen()).collect(),
                fr_seq_signed: (0..10).map(|_| r.r#gen()).collect(),
                fq: r.r#gen(),
                fq_seq: (0..10).map(|_| r.r#gen()).collect(),
                g2: r.r#gen(),
                affine: r.r#gen(),
                affine_seq: (0..10).map(|_| r.r#gen()).collect(),
            }
        }
    }

    #[test]
    fn test_human_and_non_human_readable() {
        let mut rng = rand::thread_rng();
        let should = Serializable::rand(&mut rng);
        let json_encoded = serde_json::to_vec(&should).expect("can serialize json");
        let json =
            serde_json::from_slice::<Serializable>(&json_encoded).expect("can deserialize json");

        let mut b = Vec::new();
        ciborium::into_writer(&should, &mut b).expect("can cbor serialize");
        let ciborium: Serializable =
            ciborium::from_reader(b.as_slice()).expect("can deserialize cbor");
        assert_eq!(should, ciborium);
        assert_eq!(should, json);
    }
}
