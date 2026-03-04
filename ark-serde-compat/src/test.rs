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
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_array")]
        fr_array: [ark_bn254::Fr; 10],
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_array_signed")]
        fr_array_signed: [ark_bn254::Fr; 10],
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
                fr_array: r.r#gen(),
                fr_array_signed: r.r#gen(),
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
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("only expects positive numbers"));

        // Case 3: Modulus (should fail)
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        let modulus_str = modulus.to_string();
        let json = format!(r#"{{"inner": "{modulus_str}"}}"#);
        let err = serde_json::from_str::<UnsignedWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Case 4: Modulus + 1 (should fail)
        let modulus_plus_one = &modulus + BigUint::one();
        let json = format!(r#"{{"inner": "{modulus_plus_one}"}}"#);
        let err = serde_json::from_str::<UnsignedWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Case 5: Modulus - 1 (should work)
        let modulus_minus_one = &modulus - BigUint::one();
        let json = format!(r#"{{"inner": "{modulus_minus_one}"}}"#);
        let res: UnsignedWrapper = serde_json::from_str(&json).expect("Should parse modulus - 1");
        assert_eq!(res.inner, -ark_bn254::Fr::ONE);

        // Case 6: JSON Number (not string)
        // Since deserialize_f calls deserialize_str, serde_json will expect a string token.
        // Providing a number token will cause a type mismatch error in serde_json.
        let json = r#"{"inner": 0}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is a type error
        assert!(err.to_string().contains("expected a string"));

        // Case 7: Hex string
        // BigInt::from_str is base 10.
        let json = r#"{"inner": "0x123"}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is an invalid data error (parsing failed)
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 8: zero-prefixed number
        let json = r#"{"inner": "0123"}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is an invalid leading zeros error (parsing failed)
        assert!(err.to_string().contains("invalid leading zeros"));

        // Case 9: plus-prefixed number
        let json = r#"{"inner": "+123"}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is an invalid sign error (parsing failed)
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 10: space-prefixed number
        let json = r#"{"inner": " 123"}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is an invalid data error (parsing failed)
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 11: space-postfixed number
        let json = r#"{"inner": "123 "}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is an invalid data error (parsing failed)
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 11: zero-prefixed zero
        let json = r#"{"inner": "00"}"#;
        let err = serde_json::from_str::<UnsignedWrapper>(json).expect_err("Should be an error");
        // verify it is an invalid data error (parsing failed)
        assert!(err.to_string().contains("zero must be serialized as '0'"));
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
        let json = format!(r#"{{"inner": "{modulus_str}"}}"#);
        let err = serde_json::from_str::<SignedWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Case 5: Modulus + 1 (should fail)
        let modulus_plus_one = modulus + BigUint::one();
        let json = format!(r#"{{"inner": "{modulus_plus_one}"}}"#);
        let err = serde_json::from_str::<SignedWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Case 6: -Modulus (should be 0)
        let json = format!(r#"{{"inner": "-{modulus_str}"}}"#);
        let res: SignedWrapper = serde_json::from_str(&json).expect("Should parse -Modulus");
        assert_eq!(res.inner, ark_bn254::Fr::ZERO);

        // Case 7: -(Modulus + 1) (should fail)
        let json = format!(r#"{{"inner": "-{modulus_plus_one}"}}"#);
        let err = serde_json::from_str::<SignedWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Case 8: JSON Number (not string)
        let json = r#"{"inner": 0}"#;
        let err = serde_json::from_str::<SignedWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("expected a string"));

        // Case 9: Hex string
        let json = r#"{"inner": "0x123"}"#;
        let err = serde_json::from_str::<SignedWrapper>(json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Case 10: negative Hex string
        let json = r#"{"inner": "-0x123"}"#;
        let err = serde_json::from_str::<SignedWrapper>(json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );
    }

    #[test]
    fn test_deserialize_f_array_wrong_length() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array")]
            inner: [ark_bn254::Fr; 3],
        }

        // Too few elements (2 instead of 3)
        let json = r#"{"inner": ["1", "2"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Too many elements (4 instead of 3)
        let json = r#"{"inner": ["1", "2", "3", "4"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Empty array when expecting 3
        let json = r#"{"inner": []}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn test_deserialize_f_array_invalid_elements() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array")]
            inner: [ark_bn254::Fr; 2],
        }

        // Value >= modulus
        let modulus: num_bigint::BigUint = ark_bn254::Fr::MODULUS.into();
        let json = format!(r#"{{"inner": ["{modulus}", "1"]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Negative value (unsigned rejects negatives)
        let json = r#"{"inner": ["-1", "1"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("only expects positive numbers"));

        // Non-numeric string
        let json = r#"{"inner": ["abc", "1"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );

        // Number token instead of string
        let json = r#"{"inner": [1, 2]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("expected a string"));
    }

    #[test]
    fn test_deserialize_f_array_signed_wrong_length() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array_signed")]
            inner: [ark_bn254::Fr; 3],
        }

        // Too few elements (2 instead of 3)
        let json = r#"{"inner": ["1", "2"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Too many elements (4 instead of 3)
        let json = r#"{"inner": ["1", "2", "3", "4"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Empty array when expecting 3
        let json = r#"{"inner": []}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn test_deserialize_f_array_signed_invalid_elements() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array_signed")]
            inner: [ark_bn254::Fr; 2],
        }

        // Value >= modulus
        let modulus: num_bigint::BigUint = ark_bn254::Fr::MODULUS.into();
        let json = format!(r#"{{"inner": ["{modulus}", "1"]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // Negative value exceeding modulus (-(modulus + 1))
        let modulus_plus_one = &modulus + num_bigint::BigUint::from(1u32);
        let json = format!(r#"{{"inner": ["-{modulus_plus_one}", "1"]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("doesn't fit into field"));

        // "-0" is not valid
        let json = r#"{"inner": ["-0", "1"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("zero must be serialized as '0'"));

        // Non-numeric string
        let json = r#"{"inner": ["abc", "1"]}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("only expects digits 0-9 for numbers")
        );
    }

    #[test]
    fn test_deserialize_f_array_binary_wrong_length() {
        #[derive(Serialize)]
        struct SeqWrapper {
            #[serde(serialize_with = "crate::serialize_f_seq")]
            inner: Vec<ark_bn254::Fr>,
        }

        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array")]
            inner: [ark_bn254::Fr; 3],
        }

        let mut rng = rand::thread_rng();

        // Too few elements (2 instead of 3)
        let seq = SeqWrapper {
            inner: (0..2).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Too many elements (4 instead of 3)
        let seq = SeqWrapper {
            inner: (0..4).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Empty vec when expecting 3
        let seq = SeqWrapper { inner: vec![] };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");
    }

    #[test]
    fn test_deserialize_f_array_binary_corrupted() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array")]
            inner: [ark_bn254::Fr; 3],
        }

        // Build a CBOR map {"inner": <garbage bytes>} using ciborium::Value
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let cbor_map = ciborium::Value::Map(vec![(
            ciborium::Value::Text("inner".into()),
            ciborium::Value::Bytes(garbage),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");
    }

    #[test]
    fn test_deserialize_f_array_signed_binary_wrong_length() {
        #[derive(Serialize)]
        struct SeqWrapper {
            #[serde(serialize_with = "crate::serialize_f_seq")]
            inner: Vec<ark_bn254::Fr>,
        }

        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "crate::deserialize_f_array_signed")]
            inner: [ark_bn254::Fr; 3],
        }

        let mut rng = rand::thread_rng();

        // Too few elements (2 instead of 3)
        let seq = SeqWrapper {
            inner: (0..2).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Too many elements (4 instead of 3)
        let seq = SeqWrapper {
            inner: (0..4).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Empty vec when expecting 3
        let seq = SeqWrapper { inner: vec![] };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");
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
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_array")]
        fr_array: [ark_bls12_381::Fr; 10],
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_array_signed")]
        fr_array_signed: [ark_bls12_381::Fr; 10],
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
                fr_array: r.r#gen(),
                fr_array_signed: r.r#gen(),
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
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_array")]
        fr_array: [ark_babyjubjub::Fr; 10],
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_array_signed")]
        fr_array_signed: [ark_babyjubjub::Fr; 10],
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
                fr_array: r.r#gen(),
                fr_array_signed: r.r#gen(),
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

    #[test]
    fn test_deserialize_affine_array_wrong_length() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "babyjubjub::deserialize_affine_array")]
            inner: [ark_babyjubjub::EdwardsAffine; 2],
        }

        let gen_x = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
        let gen_y = "16950150798460657717958625567821834550301663161624707787222815936182638968203";

        // Too few points (1 instead of 2)
        let json = format!(r#"{{"inner": [["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Too many points (3 instead of 2)
        let json = format!(
            r#"{{"inner": [["{gen_x}", "{gen_y}"], ["{gen_x}", "{gen_y}"], ["{gen_x}", "{gen_y}"]]}}"#
        );
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Empty array when expecting 2
        let json = r#"{"inner": []}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn test_deserialize_affine_array_invalid_points() {
        use ark_ff::PrimeField;

        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "babyjubjub::deserialize_affine_array")]
            inner: [ark_babyjubjub::EdwardsAffine; 2],
        }

        let gen_x = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
        let gen_y = "16950150798460657717958625567821834550301663161624707787222815936182638968203";

        // Non-numeric coordinate
        let json = format!(r#"{{"inner": [["notanumber", "{gen_y}"], ["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("Invalid affine point on babyjubjub")
        );

        // Point not on the curve (x=1, y=1 is not on BabyJubJub)
        let json = format!(r#"{{"inner": [["1", "1"], ["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("Invalid affine point on babyjubjub")
        );

        // Coordinate exceeding field modulus
        let fq_modulus: num_bigint::BigUint = ark_babyjubjub::Fq::MODULUS.into();
        let json = format!(r#"{{"inner": [["{fq_modulus}", "{gen_y}"], ["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(
            err.to_string()
                .contains("Invalid affine point on babyjubjub")
        );

        // Wrong coordinate count: only 1 coordinate instead of 2
        let json = format!(r#"{{"inner": [["{gen_x}"], ["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length 1"));

        // Wrong coordinate count: 3 coordinates instead of 2
        let json =
            format!(r#"{{"inner": [["{gen_x}", "{gen_y}", "{gen_x}"], ["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length 3"));
    }

    #[test]
    fn test_deserialize_affine_array_unchecked_wrong_length() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "babyjubjub::deserialize_affine_array_unchecked")]
            inner: [ark_babyjubjub::EdwardsAffine; 2],
        }

        let gen_x = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
        let gen_y = "16950150798460657717958625567821834550301663161624707787222815936182638968203";

        // Too few points (1 instead of 2)
        let json = format!(r#"{{"inner": [["{gen_x}", "{gen_y}"]]}}"#);
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Too many points (3 instead of 2)
        let json = format!(
            r#"{{"inner": [["{gen_x}", "{gen_y}"], ["{gen_x}", "{gen_y}"], ["{gen_x}", "{gen_y}"]]}}"#
        );
        let err = serde_json::from_str::<ArrayWrapper>(&json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));

        // Empty array when expecting 2
        let json = r#"{"inner": []}"#;
        let err = serde_json::from_str::<ArrayWrapper>(json).expect_err("Should be an error");
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn test_deserialize_affine_array_binary_wrong_length() {
        #[derive(Serialize)]
        struct SeqWrapper {
            #[serde(serialize_with = "babyjubjub::serialize_affine_seq")]
            inner: Vec<ark_babyjubjub::EdwardsAffine>,
        }

        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "babyjubjub::deserialize_affine_array")]
            inner: [ark_babyjubjub::EdwardsAffine; 2],
        }

        let mut rng = rand::thread_rng();

        // Too few points (1 instead of 2)
        let seq = SeqWrapper {
            inner: (0..1).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Too many points (3 instead of 2)
        let seq = SeqWrapper {
            inner: (0..3).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Empty vec when expecting 2
        let seq = SeqWrapper { inner: vec![] };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");
    }

    #[test]
    fn test_deserialize_affine_array_binary_corrupted() {
        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "babyjubjub::deserialize_affine_array")]
            inner: [ark_babyjubjub::EdwardsAffine; 2],
        }

        // Build a CBOR map {"inner": <garbage bytes>} using ciborium::Value
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let cbor_map = ciborium::Value::Map(vec![(
            ciborium::Value::Text("inner".into()),
            ciborium::Value::Bytes(garbage),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cbor_map, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");
    }

    #[test]
    fn test_deserialize_affine_array_unchecked_binary_wrong_length() {
        #[derive(Serialize)]
        struct SeqWrapper {
            #[serde(serialize_with = "babyjubjub::serialize_affine_seq")]
            inner: Vec<ark_babyjubjub::EdwardsAffine>,
        }

        #[derive(Deserialize, Debug)]
        #[allow(
            dead_code,
            reason = "we only need inner for deserialization - never really used"
        )]
        struct ArrayWrapper {
            #[serde(deserialize_with = "babyjubjub::deserialize_affine_array_unchecked")]
            inner: [ark_babyjubjub::EdwardsAffine; 2],
        }

        let mut rng = rand::thread_rng();

        // Too few points (1 instead of 2)
        let seq = SeqWrapper {
            inner: (0..1).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Too many points (3 instead of 2)
        let seq = SeqWrapper {
            inner: (0..3).map(|_| rng.r#gen()).collect(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");

        // Empty vec when expecting 2
        let seq = SeqWrapper { inner: vec![] };
        let mut buf = Vec::new();
        ciborium::into_writer(&seq, &mut buf).expect("can cbor serialize");
        ciborium::from_reader::<ArrayWrapper, _>(buf.as_slice()).expect_err("Should be an error");
    }
}
