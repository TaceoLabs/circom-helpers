//! Known-answer tests for the serde compatibility implementations.
//!
//! The vectors in `tests/kats/` were generated with `taceo-ark-serde-compat 0.5.0`.
//! The vectors in `tests/kats/v0.6.1/` cover every serde helper of the crate and were generated with `taceo-ark-serde-compat 0.6.1`.
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

macro_rules! curve_kats {
    ($modname:ident, $feature:literal, $c:ident, $cm:ident, $pairing:ident, $name:literal) => {
        #[cfg(feature = $feature)]
        mod $modname {
            use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
            use ark_ff::{AdditiveGroup, Field};
            use serde::{Deserialize, Serialize};
            use taceo_ark_serde_compat::$cm as cm;
            use $c as c;

            const JSON_KAT: &str = include_str!(concat!("kats/v0.6.1/", $name, ".json"));
            const CBOR_KAT: &[u8] = include_bytes!(concat!("kats/v0.6.1/", $name, ".cbor"));

            #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
            struct Kat {
                #[serde(with = "taceo_ark_serde_compat::field")]
                fr_zero: c::Fr,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fr_one: c::Fr,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fr_minus_one: c::Fr,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fr_large: c::Fr,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fq_zero: c::Fq,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fq_one: c::Fq,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fq_minus_one: c::Fq,
                #[serde(with = "taceo_ark_serde_compat::field")]
                fq_large: c::Fq,
                #[serde(with = "taceo_ark_serde_compat::field_signed")]
                fr_signed_minus_one: c::Fr,
                #[serde(with = "taceo_ark_serde_compat::field_signed")]
                fr_signed_large: c::Fr,
                #[serde(with = "taceo_ark_serde_compat::field_seq")]
                fr_seq: Vec<c::Fr>,
                #[serde(with = "taceo_ark_serde_compat::field_seq")]
                fr_seq_empty: Vec<c::Fr>,
                #[serde(with = "taceo_ark_serde_compat::field_seq_signed")]
                fr_seq_signed: Vec<c::Fr>,
                #[serde(with = "taceo_ark_serde_compat::field_seq_signed")]
                fr_seq_signed_empty: Vec<c::Fr>,
                #[serde(
                    serialize_with = "taceo_ark_serde_compat::serialize_f_seq",
                    deserialize_with = "taceo_ark_serde_compat::deserialize_f_array::<3, _, _>"
                )]
                fr_array: [c::Fr; 3],
                #[serde(
                    serialize_with = "taceo_ark_serde_compat::serialize_f_seq",
                    deserialize_with = "taceo_ark_serde_compat::deserialize_f_array_signed::<3, _, _>"
                )]
                fr_array_signed: [c::Fr; 3],
                #[serde(with = "cm::g1")]
                g1_gen: c::G1Affine,
                #[serde(with = "cm::g1")]
                g1_mul: c::G1Affine,
                #[serde(with = "cm::g1")]
                g1_inf: c::G1Affine,
                #[serde(with = "cm::g1_unchecked")]
                g1_unchecked_gen: c::G1Affine,
                #[serde(with = "cm::g1_unchecked")]
                g1_unchecked_mul: c::G1Affine,
                #[serde(with = "cm::g1_unchecked")]
                g1_unchecked_inf: c::G1Affine,
                #[serde(with = "cm::g2")]
                g2_gen: c::G2Affine,
                #[serde(with = "cm::g2")]
                g2_mul: c::G2Affine,
                #[serde(with = "cm::g2")]
                g2_inf: c::G2Affine,
                #[serde(with = "cm::g2_unchecked")]
                g2_unchecked_gen: c::G2Affine,
                #[serde(with = "cm::g2_unchecked")]
                g2_unchecked_mul: c::G2Affine,
                #[serde(with = "cm::g2_unchecked")]
                g2_unchecked_inf: c::G2Affine,
                #[serde(with = "cm::gt")]
                gt_one: c::Fq12,
                #[serde(with = "cm::gt")]
                gt_pairing: c::Fq12,
                #[serde(with = "cm::g1_seq")]
                g1_seq: Vec<c::G1Affine>,
                #[serde(with = "cm::g1_seq")]
                g1_seq_empty: Vec<c::G1Affine>,
                #[serde(with = "cm::g1_seq_unchecked")]
                g1_seq_unchecked: Vec<c::G1Affine>,
                #[serde(with = "cm::g1_seq_unchecked")]
                g1_seq_unchecked_empty: Vec<c::G1Affine>,
            }

            fn expected() -> Kat {
                let g1 = c::G1Affine::generator();
                let g1_mul = (g1 * c::Fr::from(42u64)).into_affine();
                let g1_inf = c::G1Affine::identity();
                let g2 = c::G2Affine::generator();
                let g2_mul = (g2 * c::Fr::from(42u64)).into_affine();
                let g2_inf = c::G2Affine::identity();
                let fr_large = c::Fr::from(0xdead_beef_u64).pow([5]);
                let fr_seq = vec![
                    c::Fr::ZERO,
                    c::Fr::ONE,
                    -c::Fr::ONE,
                    fr_large,
                    c::Fr::from(7u64),
                ];
                Kat {
                    fr_zero: c::Fr::ZERO,
                    fr_one: c::Fr::ONE,
                    fr_minus_one: -c::Fr::ONE,
                    fr_large,
                    fq_zero: c::Fq::ZERO,
                    fq_one: c::Fq::ONE,
                    fq_minus_one: -c::Fq::ONE,
                    fq_large: c::Fq::from(0xdead_beef_u64).pow([5]),
                    fr_signed_minus_one: -c::Fr::ONE,
                    fr_signed_large: fr_large,
                    fr_seq: fr_seq.clone(),
                    fr_seq_empty: vec![],
                    fr_seq_signed: fr_seq,
                    fr_seq_signed_empty: vec![],
                    fr_array: [c::Fr::ZERO, c::Fr::ONE, -c::Fr::ONE],
                    fr_array_signed: [fr_large, c::Fr::from(7u64), -c::Fr::ONE],
                    g1_gen: g1,
                    g1_mul,
                    g1_inf,
                    g1_unchecked_gen: g1,
                    g1_unchecked_mul: g1_mul,
                    g1_unchecked_inf: g1_inf,
                    g2_gen: g2,
                    g2_mul,
                    g2_inf,
                    g2_unchecked_gen: g2,
                    g2_unchecked_mul: g2_mul,
                    g2_unchecked_inf: g2_inf,
                    gt_one: c::Fq12::ONE,
                    gt_pairing: c::$pairing::pairing(g1, g2).0,
                    g1_seq: vec![g1, g1_mul, g1_inf],
                    g1_seq_empty: vec![],
                    g1_seq_unchecked: vec![g1, g1_mul, g1_inf],
                    g1_seq_unchecked_empty: vec![],
                }
            }

            #[test]
            fn json_kat() {
                let serialized = serde_json::to_string(&expected()).expect("can serialize json");
                assert_eq!(serialized, JSON_KAT, "JSON serialization changed");
                let deserialized: Kat =
                    serde_json::from_str(JSON_KAT).expect("can deserialize json KAT");
                assert_eq!(deserialized, expected(), "JSON deserialization changed");
            }

            #[test]
            fn cbor_kat() {
                let mut serialized = Vec::new();
                ciborium::into_writer(&expected(), &mut serialized).expect("can serialize cbor");
                assert_eq!(serialized, CBOR_KAT, "CBOR serialization changed");
                let deserialized: Kat =
                    ciborium::from_reader(CBOR_KAT).expect("can deserialize cbor KAT");
                assert_eq!(deserialized, expected(), "CBOR deserialization changed");
            }

            #[test]
            fn signed_json_input() {
                #[derive(Debug, PartialEq, Deserialize)]
                struct Signed {
                    #[serde(with = "taceo_ark_serde_compat::field_signed")]
                    single: c::Fr,
                    #[serde(with = "taceo_ark_serde_compat::field_seq_signed")]
                    seq: Vec<c::Fr>,
                    #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f_array_signed::<2, _, _>")]
                    array: [c::Fr; 2],
                }
                let got: Signed =
                    serde_json::from_str(r#"{"single":"-1","seq":["-1","-42","5"],"array":["-42","-1"]}"#)
                        .expect("can deserialize signed input");
                assert_eq!(
                    got,
                    Signed {
                        single: -c::Fr::ONE,
                        seq: vec![-c::Fr::ONE, -c::Fr::from(42u64), c::Fr::from(5u64)],
                        array: [-c::Fr::from(42u64), -c::Fr::ONE],
                    }
                );
            }
        }
    };
}

curve_kats!(bn254_full, "bn254", ark_bn254, bn254, Bn254, "bn254");
curve_kats!(
    bls12_381_full,
    "bls12-381",
    ark_bls12_381,
    bls12_381,
    Bls12_381,
    "bls12_381"
);

#[cfg(feature = "babyjubjub")]
mod babyjubjub_full {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{AdditiveGroup, Field};
    use serde::{Deserialize, Serialize};
    use taceo_ark_serde_compat::babyjubjub as bjj;

    type Fr = ark_babyjubjub::Fr;
    type Fq = ark_babyjubjub::Fq;
    type P = ark_babyjubjub::EdwardsAffine;

    const JSON_KAT: &str = include_str!("kats/v0.6.1/babyjubjub.json");
    const CBOR_KAT: &[u8] = include_bytes!("kats/v0.6.1/babyjubjub.cbor");

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Kat {
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_zero: Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_one: Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_minus_one: Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fr_large: Fr,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_zero: Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_one: Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_minus_one: Fq,
        #[serde(with = "taceo_ark_serde_compat::field")]
        fq_large: Fq,
        #[serde(with = "taceo_ark_serde_compat::field_signed")]
        fr_signed_minus_one: Fr,
        #[serde(with = "taceo_ark_serde_compat::field_seq")]
        fr_seq: Vec<Fr>,
        #[serde(with = "taceo_ark_serde_compat::field_seq")]
        fr_seq_empty: Vec<Fr>,
        #[serde(with = "taceo_ark_serde_compat::field_seq_signed")]
        fr_seq_signed: Vec<Fr>,
        #[serde(
            serialize_with = "taceo_ark_serde_compat::serialize_f_seq",
            deserialize_with = "taceo_ark_serde_compat::deserialize_f_array::<3, _, _>"
        )]
        fr_array: [Fr; 3],
        #[serde(
            serialize_with = "taceo_ark_serde_compat::serialize_f_seq",
            deserialize_with = "taceo_ark_serde_compat::deserialize_f_array_signed::<3, _, _>"
        )]
        fr_array_signed: [Fr; 3],
        #[serde(with = "bjj::affine")]
        point_gen: P,
        #[serde(with = "bjj::affine")]
        point_mul: P,
        #[serde(with = "bjj::affine")]
        point_inf: P,
        #[serde(with = "bjj::affine_unchecked")]
        point_unchecked_gen: P,
        #[serde(with = "bjj::affine_unchecked")]
        point_unchecked_mul: P,
        #[serde(with = "bjj::affine_unchecked")]
        point_unchecked_inf: P,
        #[serde(with = "bjj::affine_seq")]
        point_seq: Vec<P>,
        #[serde(with = "bjj::affine_seq")]
        point_seq_empty: Vec<P>,
        #[serde(with = "bjj::affine_seq_unchecked")]
        point_seq_unchecked: Vec<P>,
        #[serde(with = "bjj::affine_seq_unchecked")]
        point_seq_unchecked_empty: Vec<P>,
        #[serde(
            serialize_with = "bjj::serialize_affine_seq",
            deserialize_with = "bjj::deserialize_affine_array::<3, _>"
        )]
        point_array: [P; 3],
        #[serde(
            serialize_with = "bjj::serialize_affine_seq",
            deserialize_with = "bjj::deserialize_affine_array_unchecked::<3, _>"
        )]
        point_array_unchecked: [P; 3],
    }

    fn expected() -> Kat {
        let gen_p = P::generator();
        let mul = (gen_p * Fr::from(42u64)).into_affine();
        let inf = P::zero();
        let fr_large = Fr::from(0xdead_beef_u64).pow([5]);
        let fr_seq = vec![Fr::ZERO, Fr::ONE, -Fr::ONE, fr_large, Fr::from(7u64)];
        Kat {
            fr_zero: Fr::ZERO,
            fr_one: Fr::ONE,
            fr_minus_one: -Fr::ONE,
            fr_large,
            fq_zero: Fq::ZERO,
            fq_one: Fq::ONE,
            fq_minus_one: -Fq::ONE,
            fq_large: Fq::from(0xdead_beef_u64).pow([5]),
            fr_signed_minus_one: -Fr::ONE,
            fr_seq: fr_seq.clone(),
            fr_seq_empty: vec![],
            fr_seq_signed: fr_seq,
            fr_array: [Fr::ZERO, Fr::ONE, -Fr::ONE],
            fr_array_signed: [fr_large, Fr::from(7u64), -Fr::ONE],
            point_gen: gen_p,
            point_mul: mul,
            point_inf: inf,
            point_unchecked_gen: gen_p,
            point_unchecked_mul: mul,
            point_unchecked_inf: inf,
            point_seq: vec![gen_p, mul, inf],
            point_seq_empty: vec![],
            point_seq_unchecked: vec![gen_p, mul, inf],
            point_seq_unchecked_empty: vec![],
            point_array: [gen_p, mul, inf],
            point_array_unchecked: [gen_p, mul, inf],
        }
    }

    #[test]
    fn json_kat() {
        let serialized = serde_json::to_string(&expected()).expect("can serialize json");
        assert_eq!(serialized, JSON_KAT, "JSON serialization changed");
        let deserialized: Kat = serde_json::from_str(JSON_KAT).expect("can deserialize json KAT");
        assert_eq!(deserialized, expected(), "JSON deserialization changed");
    }

    #[test]
    fn cbor_kat() {
        let mut serialized = Vec::new();
        ciborium::into_writer(&expected(), &mut serialized).expect("can serialize cbor");
        assert_eq!(serialized, CBOR_KAT, "CBOR serialization changed");
        let deserialized: Kat = ciborium::from_reader(CBOR_KAT).expect("can deserialize cbor KAT");
        assert_eq!(deserialized, expected(), "CBOR deserialization changed");
    }
}
