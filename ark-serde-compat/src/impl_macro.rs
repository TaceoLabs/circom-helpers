macro_rules! impl_json_canonical {
    ($curve: ident, $curve_impl: ident, $mod: ident) => {
        #[doc = concat!(
            "Serialization and deserialization functions for ",
            stringify!($curve_impl),
            " curve types.\n\n",
            "This module provides serde-compatible serialization and deserialization functions\n",
            "for ",
            stringify!($curve_impl),
            " curve types, including field elements (Fr, Fq) and curve points (G1, G2, GT).\n\n",
            "All field elements are serialized as decimal strings. G1 and G2 points are serialized\n",
            "in projective coordinates as arrays of coordinate strings. GT elements are serialized\n",
            "as nested arrays representing the Fq12 structure."
        )]
        pub mod $mod {
            use crate::{CanonicalJsonSerialize};
            use serde::{Serializer, de};
            use ark_ff::QuadExtConfig;

            impl CanonicalJsonSerialize for $curve::$curve_impl {
                fn serialize_g1<S: Serializer>(p: &Self::G1Affine, ser: S) -> Result<S::Ok, S::Error> {
                    crate::serialize_g1(p, ser)
                }

                fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error> {
                    crate::serialize_g2(p, ser)
                }

                fn serialize_gt<S: Serializer>(
                    p: &Self::TargetField,
                    ser: S,
                ) -> Result<S::Ok, S::Error> {
                    crate::serialize_gt(p, ser)
                }

                fn serialize_g1_seq<S: Serializer>(
                    p: &[Self::G1Affine],
                    ser: S,
                ) -> Result<S::Ok, S::Error> {
                    crate::serialize_g1_seq(p, ser)
                }

                fn deserialize_g1<'de, D>(deserializer: D) -> Result<Self::G1Affine, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_g1(deserializer)
                }

                fn deserialize_g1_unchecked<'de, D>(deserializer: D) -> Result<Self::G1Affine, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_g1_unchecked(deserializer)
                }

                fn deserialize_g2<'de, D>(deserializer: D) -> Result<Self::G2Affine, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_g2(deserializer)
                }

                fn deserialize_g2_unchecked<'de, D>(deserializer: D) -> Result<Self::G2Affine, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_g2_unchecked(deserializer)
                }

                fn deserialize_gt<'de, D>(deserializer: D) -> Result<Self::TargetField, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_gt(deserializer)
                }

                fn deserialize_g1_seq<'de, D>(deserializer: D) -> Result<Vec<Self::G1Affine>, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_g1_seq(deserializer)
                }

                fn deserialize_g1_seq_unchecked<'de, D>(
                    deserializer: D,
                ) -> Result<Vec<Self::G1Affine>, D::Error>
                where
                    D: de::Deserializer<'de>,
                {
                    crate::deserialize_g1_seq_unchecked(deserializer)
                }
            }

            #[doc = concat!(
                "Serializes a ",
                stringify!($curve_impl),
                " G1 point as an array of three coordinate strings.\n\n",
                "The G1 point is serialized in projective coordinates as `[x, y, z]`, where each\n",
                "coordinate is a decimal string. The point at infinity is represented as `[\"0\", \"1\", \"0\"]`.\n\n",
                "This helper forwards to `crate::serialize_g1`."
            )]
            pub fn serialize_g1<S: Serializer>(
                p: &$curve::G1Affine,
                ser: S,
            ) -> Result<S::Ok, S::Error> {
                crate::serialize_g1(p, ser)
            }

            #[doc = concat!(
                "Serializes a ",
                stringify!($curve_impl),
                " G2 point as a 3×2 array of coordinate strings.\n\n",
                "The G2 point is serialized in projective coordinates as `[[x0, x1], [y0, y1], [z0, z1]]`,\n",
                "where each projective coordinate is an Fq2 element represented by a pair of decimal strings.\n\n",
                "This helper forwards to `crate::serialize_g2`."
            )]
            pub fn serialize_g2<F, S: Serializer>(p: &$curve::G2Affine, ser: S) -> Result<S::Ok, S::Error>
            where
                F: QuadExtConfig,
            {
                crate::serialize_g2(p, ser)
            }

            #[doc = concat!(
                "Serializes a ",
                stringify!($curve_impl),
                " GT (target group) element as a 2×3×2 array of decimal strings.\n\n",
                "An Fq12 element is viewed as two Fq6 components, each containing three Fq2 components.\n",
                "Each Fq2 component is serialized as `[c0, c1]` with decimal strings, yielding the overall\n",
                "structure `[[[a0, a1], [b0, b1], [c0, c1]], [[d0, d1], [e0, e1], [f0, f1]]]`.\n\n",
                "This helper forwards to `crate::serialize_gt`."
            )]
            pub fn serialize_gt<S: Serializer>(p: &$curve::Fq12, ser: S) -> Result<S::Ok, S::Error> {
                crate::serialize_gt(p, ser)
            }

            #[doc = concat!(
                "Serializes a sequence of ",
                stringify!($curve_impl),
                " G1 points as an array of projective coordinate arrays.\n\n",
                "Each G1 point is serialized as `[x, y, z]` with decimal strings. The point at infinity uses\n",
                "the fixed sentinel `[\"0\", \"1\", \"0\"]`.\n\n",
                "This helper forwards to `crate::serialize_g1_seq`."
            )]
            pub fn serialize_g1_seq<S: Serializer>(
                ps: &[$curve::G1Affine],
                ser: S,
            ) -> Result<S::Ok, S::Error> {
                crate::serialize_g1_seq(ps, ser)
            }

            #[doc = concat!(
                "Deserializes a single ",
                stringify!($curve_impl),
                " G1 point from its `[x, y, z]` projective decimal string representation.\n\n",
                "Performs full validation (field element decoding, on-curve check, subgroup membership) and\n",
                "returns an affine point. The point at infinity must appear exactly as `[\"0\", \"1\", \"0\"]`.\n\n",
                "For a faster variant that skips safety checks, see `deserialize_g1_unchecked`."
            )]
            pub fn deserialize_g1<'de, D>(deserializer: D) -> Result<$curve::G1Affine, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                crate::deserialize_g1(deserializer)
            }

            #[doc = concat!(
                "Deserializes a single ",
                stringify!($curve_impl),
                " G1 point from its `[x, y, z]` projective decimal string representation WITHOUT safety checks.\n\n",
                "This unchecked variant skips:\n",
                "- Field element canonical form checks\n",
                "- On-curve validation\n",
                "- Subgroup membership verification\n\n",
                "It should only be used when the input is guaranteed trustworthy (e.g. previously validated or\n",
                "produced internally). Misuse can lead to invalid points and downstream security issues.\n\n",
                "Returns an affine point. The point at infinity must still be `[\"0\", \"1\", \"0\"]`."
            )]
            pub fn deserialize_g1_unchecked<'de, D>(deserializer: D) -> Result<$curve::G1Affine, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                crate::deserialize_g1_unchecked(deserializer)
            }

            #[doc = concat!(
                "Deserializes a single ",
                stringify!($curve_impl),
                " G2 point from its `[[x0, x1], [y0, y1], [z0, z1]]` projective decimal string representation.\n\n",
                "Performs full validation (field decoding, on-curve, subgroup) and returns an affine point.\n",
                "Use `deserialize_g2_unchecked` if you need performance and already trust the source."
            )]
            pub fn deserialize_g2<'de, D>(deserializer: D) -> Result<$curve::G2Affine, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                crate::deserialize_g2(deserializer)
            }

            #[doc = concat!(
                "Deserializes a single ",
                stringify!($curve_impl),
                " G2 point from its `[[x0, x1], [y0, y1], [z0, z1]]` projective decimal string representation WITHOUT safety checks.\n\n",
                "Skipped validations:\n",
                "- Field element canonical form\n",
                "- On-curve check\n",
                "- Subgroup membership\n\n",
                "Only use when the input is known-good. Returns an affine point."
            )]
            pub fn deserialize_g2_unchecked<'de, D>(deserializer: D) -> Result<$curve::G2Affine, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                crate::deserialize_g2_unchecked(deserializer)
            }

            #[doc = concat!(
                "Deserializes a ",
                stringify!($curve_impl),
                " GT (Fq12) element from its 2×3×2 decimal string representation.\n\n",
                "Performs full validation of all component field elements. Returns an `Fq12` value."
            )]
            pub fn deserialize_gt<'de, D>(deserializer: D) -> Result<$curve::Fq12, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                super::deserialize_gt(deserializer)
            }

            #[doc = concat!(
                "Deserializes a sequence of ",
                stringify!($curve_impl),
                " G1 points from an array of `[x, y, z]` projective decimal string triples.\n\n",
                "Each element is fully validated. The point at infinity must be `[\"0\", \"1\", \"0\"]`."
            )]
            pub fn deserialize_g1_seq<'de, D>(deserializer: D) -> Result<Vec<$curve::G1Affine>, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                super::deserialize_g1_seq(deserializer)
            }

            #[doc = concat!(
                "Deserializes a sequence of ",
                stringify!($curve_impl),
                " G1 points from an array of `[x, y, z]` projective decimal string triples WITHOUT safety checks.\n\n",
                "Skipped validations for each point:\n",
                "- Field element canonical form\n",
                "- On-curve check\n",
                "- Subgroup membership\n\n",
                "Only use when all inputs are guaranteed valid."
            )]
            pub fn deserialize_g1_seq_unchecked<'de, D>(deserializer: D) -> Result<Vec<$curve::G1Affine>, D::Error>
            where
                D: de::Deserializer<'de>,
            {
                super::deserialize_g1_seq_unchecked(deserializer)
            }
        }
    };
}

pub(crate) use impl_json_canonical;
