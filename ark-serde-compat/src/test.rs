#[cfg(feature = "bn254")]
mod bn254_tests {
    use crate::bn254;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fr: ark_bn254::Fr,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fr_seq: Vec<ark_bn254::Fr>,
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
                fr: r.r#gen(),
                fr_seq: (0..10).map(|_| r.r#gen()).collect(),
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
    fn test_json_cbor() {
        let mut rng = rand::thread_rng();
        let should = Serializable::rand(&mut rng);
        let json_encoded = serde_json::to_vec(&should).expect("can serialize json");
        let mut b = Vec::new();

        ciborium::into_writer(&should, &mut b).expect("can cbor serialize");
        let bincode_encoded = bincode::serde::encode_to_vec(&should, bincode::config::standard())
            .expect("can serialize bytes");

        let (bincode, _) = bincode::serde::borrow_decode_from_slice::<Serializable, _>(
            &bincode_encoded,
            bincode::config::standard(),
        )
        .expect("can deserialize bytes");
        let json =
            serde_json::from_slice::<Serializable>(&json_encoded).expect("can deserialize json");

        let ciborium: Serializable =
            ciborium::from_reader(b.as_slice()).expect("can deserialize cbor");
        assert_eq!(should, ciborium);
        assert_eq!(ciborium, json);
        assert_eq!(json, bincode);
    }
}

#[cfg(feature = "bls12-381")]
mod bls12_381_tests {
    use crate::bls12_381;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fr: ark_bls12_381::Fr,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fr_seq: Vec<ark_bls12_381::Fr>,
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
                fr: r.r#gen(),
                fr_seq: (0..10).map(|_| r.r#gen()).collect(),
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
    fn test_json_cbor() {
        let mut rng = rand::thread_rng();
        let should = Serializable::rand(&mut rng);
        let json_encoded = serde_json::to_vec(&should).expect("can serialize json");
        let mut b = Vec::new();

        ciborium::into_writer(&should, &mut b).expect("can cbor serialize");
        let bincode_encoded = bincode::serde::encode_to_vec(&should, bincode::config::standard())
            .expect("can serialize bytes");

        let (bincode, _) = bincode::serde::borrow_decode_from_slice::<Serializable, _>(
            &bincode_encoded,
            bincode::config::standard(),
        )
        .expect("can deserialize bytes");
        let json =
            serde_json::from_slice::<Serializable>(&json_encoded).expect("can deserialize json");

        let ciborium: Serializable =
            ciborium::from_reader(b.as_slice()).expect("can deserialize cbor");
        assert_eq!(should, ciborium);
        assert_eq!(ciborium, json);
        assert_eq!(json, bincode);
    }
}

#[cfg(feature = "babyjubjub")]
mod babyjubjub_test {
    use crate::babyjubjub;
    use rand::Rng;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Serializable {
        #[serde(serialize_with = "crate::serialize_f")]
        #[serde(deserialize_with = "crate::deserialize_f")]
        fr: ark_babyjubjub::Fr,
        #[serde(serialize_with = "crate::serialize_f_seq")]
        #[serde(deserialize_with = "crate::deserialize_f_seq")]
        fr_seq: Vec<ark_babyjubjub::Fr>,
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
                fr: r.r#gen(),
                fr_seq: (0..10).map(|_| r.r#gen()).collect(),
                fq: r.r#gen(),
                fq_seq: (0..10).map(|_| r.r#gen()).collect(),
                g2: r.r#gen(),
                affine: r.r#gen(),
                affine_seq: (0..10).map(|_| r.r#gen()).collect(),
            }
        }
    }

    #[test]
    fn test_json_cbor() {
        let mut rng = rand::thread_rng();
        let should = Serializable::rand(&mut rng);
        let json_encoded = serde_json::to_vec(&should).expect("can serialize json");
        let mut b = Vec::new();

        ciborium::into_writer(&should, &mut b).expect("can cbor serialize");
        let bincode_encoded = bincode::serde::encode_to_vec(&should, bincode::config::standard())
            .expect("can serialize bytes");

        let (bincode, _) = bincode::serde::borrow_decode_from_slice::<Serializable, _>(
            &bincode_encoded,
            bincode::config::standard(),
        )
        .expect("can deserialize bytes");
        let json =
            serde_json::from_slice::<Serializable>(&json_encoded).expect("can deserialize json");

        let ciborium: Serializable =
            ciborium::from_reader(b.as_slice()).expect("can deserialize cbor");
        assert_eq!(should, ciborium);
        assert_eq!(ciborium, json);
        assert_eq!(json, bincode);
    }
}
