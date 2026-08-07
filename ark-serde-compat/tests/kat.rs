//! Known-answer tests for the serde compatibility implementations.
//!
//! The vectors in `tests/kats/` were generated with `taceo-ark-serde-compat 0.5.0`
//! This ensures that the serialization format is stable and compatible with older and future versions of the crate.

#[cfg(feature = "bn254")]
mod bn254_kats {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, Field};
    use serde::{Deserialize, Serialize};
    use taceo_ark_serde_compat::bn254;

    const JSON_KAT: &str = include_str!("kats/bn254.json");
    const CBOR_KAT: &[u8] = include_bytes!("kats/bn254.cbor");

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Bn254Kat {
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_zero: ark_bn254::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_one: ark_bn254::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_minus_one: ark_bn254::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_large: ark_bn254::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_zero: ark_bn254::Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_one: ark_bn254::Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_minus_one: ark_bn254::Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_large: ark_bn254::Fq,
        #[serde(with = "bn254::g1")]
        g1_gen: ark_bn254::G1Affine,
        #[serde(with = "bn254::g1")]
        g1_mul: ark_bn254::G1Affine,
        #[serde(with = "bn254::g1")]
        g1_inf: ark_bn254::G1Affine,
        #[serde(with = "bn254::g2")]
        g2_gen: ark_bn254::G2Affine,
        #[serde(with = "bn254::g2")]
        g2_mul: ark_bn254::G2Affine,
    }

    fn expected() -> Bn254Kat {
        Bn254Kat {
            fr_zero: ark_bn254::Fr::ZERO,
            fr_one: ark_bn254::Fr::ONE,
            fr_minus_one: -ark_bn254::Fr::ONE,
            fr_large: ark_bn254::Fr::from(0xdead_beef_u64).pow([5]),
            fq_zero: ark_bn254::Fq::ZERO,
            fq_one: ark_bn254::Fq::ONE,
            fq_minus_one: -ark_bn254::Fq::ONE,
            fq_large: ark_bn254::Fq::from(0xdead_beef_u64).pow([5]),
            g1_gen: ark_bn254::G1Affine::generator(),
            g1_mul: (ark_bn254::G1Affine::generator() * ark_bn254::Fr::from(42u64)).into_affine(),
            g1_inf: ark_bn254::G1Affine::identity(),
            g2_gen: ark_bn254::G2Affine::generator(),
            g2_mul: (ark_bn254::G2Affine::generator() * ark_bn254::Fr::from(42u64)).into_affine(),
        }
    }

    #[test]
    fn json_kat() {
        let serialized = serde_json::to_string(&expected()).expect("can serialize json");
        assert_eq!(serialized, JSON_KAT, "JSON serialization changed");
        let deserialized: Bn254Kat =
            serde_json::from_str(JSON_KAT).expect("can deserialize json KAT");
        assert_eq!(deserialized, expected(), "JSON deserialization changed");
    }

    #[test]
    fn cbor_kat() {
        let mut serialized = Vec::new();
        ciborium::into_writer(&expected(), &mut serialized).expect("can serialize cbor");
        assert_eq!(serialized, CBOR_KAT, "CBOR serialization changed");
        let deserialized: Bn254Kat =
            ciborium::from_reader(CBOR_KAT).expect("can deserialize cbor KAT");
        assert_eq!(deserialized, expected(), "CBOR deserialization changed");
    }
}

#[cfg(feature = "babyjubjub")]
mod babyjubjub_kats {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, Field};
    use serde::{Deserialize, Serialize};
    use taceo_ark_serde_compat::babyjubjub;

    const JSON_KAT: &str = include_str!("kats/babyjubjub.json");
    const CBOR_KAT: &[u8] = include_bytes!("kats/babyjubjub.cbor");

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct BabyJubJubKat {
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_zero: ark_babyjubjub::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_one: ark_babyjubjub::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_minus_one: ark_babyjubjub::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_large: ark_babyjubjub::Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_zero: ark_babyjubjub::Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_one: ark_babyjubjub::Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_minus_one: ark_babyjubjub::Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_large: ark_babyjubjub::Fq,
        #[serde(with = "babyjubjub::affine")]
        point_gen: ark_babyjubjub::EdwardsAffine,
        #[serde(with = "babyjubjub::affine")]
        point_mul: ark_babyjubjub::EdwardsAffine,
        #[serde(with = "babyjubjub::affine")]
        point_inf: ark_babyjubjub::EdwardsAffine,
    }

    fn expected() -> BabyJubJubKat {
        BabyJubJubKat {
            fr_zero: ark_babyjubjub::Fr::ZERO,
            fr_one: ark_babyjubjub::Fr::ONE,
            fr_minus_one: -ark_babyjubjub::Fr::ONE,
            fr_large: ark_babyjubjub::Fr::from(0xdead_beef_u64).pow([5]),
            fq_zero: ark_babyjubjub::Fq::ZERO,
            fq_one: ark_babyjubjub::Fq::ONE,
            fq_minus_one: -ark_babyjubjub::Fq::ONE,
            fq_large: ark_babyjubjub::Fq::from(0xdead_beef_u64).pow([5]),
            point_gen: ark_babyjubjub::EdwardsAffine::generator(),
            point_mul: (ark_babyjubjub::EdwardsAffine::generator()
                * ark_babyjubjub::Fr::from(42u64))
            .into_affine(),
            point_inf: ark_babyjubjub::EdwardsAffine::zero(),
        }
    }

    #[test]
    fn json_kat() {
        let serialized = serde_json::to_string(&expected()).expect("can serialize json");
        assert_eq!(serialized, JSON_KAT, "JSON serialization changed");
        let deserialized: BabyJubJubKat =
            serde_json::from_str(JSON_KAT).expect("can deserialize json KAT");
        assert_eq!(deserialized, expected(), "JSON deserialization changed");
    }

    #[test]
    fn cbor_kat() {
        let mut serialized = Vec::new();
        ciborium::into_writer(&expected(), &mut serialized).expect("can serialize cbor");
        assert_eq!(serialized, CBOR_KAT, "CBOR serialization changed");
        let deserialized: BabyJubJubKat =
            ciborium::from_reader(CBOR_KAT).expect("can deserialize cbor KAT");
        assert_eq!(deserialized, expected(), "CBOR deserialization changed");
    }
}
