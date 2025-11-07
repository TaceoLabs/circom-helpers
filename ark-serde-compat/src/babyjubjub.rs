//! Serialization and deserialization functions for BabyJubJub curve types.
//!
//! This module provides serde-compatible serialization and deserialization functions
//! for BabyJubJub curve types, including field elements (Fr, Fq) and curve points
//! (EdwardsAffine).
//!
//! All field elements are serialized as decimal strings. Curve points are serialized
//! in affine coordinates as arrays of two coordinate strings.

use serde::{
    Serializer,
    de::{self},
    ser::SerializeSeq as _,
};
use std::str::FromStr;

use crate::SerdeCompatError;

/// Serialize a BabyJubJub Fr (scalar field) element as a decimal string.
///
/// The Fr field element is serialized to its decimal string representation.
pub fn serialize_fr<S: Serializer>(
    f: &taceo_ark_babyjubjub::Fr,
    ser: S,
) -> Result<S::Ok, S::Error> {
    super::serialize_f(f, ser)
}

/// Serialize a BabyJubJub Fq (base field) element as a decimal string.
///
/// The Fq field element is serialized to its decimal string representation.
pub fn serialize_fq<S: Serializer>(
    f: &taceo_ark_babyjubjub::Fq,
    ser: S,
) -> Result<S::Ok, S::Error> {
    super::serialize_f(f, ser)
}

/// Serialize a BabyJubJub affine point as an array of two coordinate strings.
///
/// The EdwardsAffine point is serialized as `[x, y]` where each coordinate
/// is a decimal string representing an Fq element.
pub fn serialize_babyjubjub_affine<S: Serializer>(
    p: &taceo_ark_babyjubjub::EdwardsAffine,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let (x, y) = (p.x, p.y);
    let mut x_seq = ser.serialize_seq(Some(2))?;
    x_seq.serialize_element(&x.to_string())?;
    x_seq.serialize_element(&y.to_string())?;
    x_seq.end()
}

/// Serialize a sequence of BabyJubJub affine points as an array of coordinate pair arrays.
///
/// Each EdwardsAffine point is serialized as `[x, y]` where each coordinate is a decimal string.
pub fn serialize_babyjubjub_affine_sequence<S: Serializer>(
    ps: &[taceo_ark_babyjubjub::EdwardsAffine],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        let (x, y) = (p.x, p.y);
        seq.serialize_element(&[x.to_string(), y.to_string()])?;
    }
    seq.end()
}

/// Serialize a BabyJubJub Fq element as a decimal string.
///
/// This function is an alias for compatibility. Use `serialize_fq` for consistency.
pub fn serialize_babyjubjub_fq<S: Serializer>(
    p: &taceo_ark_babyjubjub::Fq,
    ser: S,
) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&p.to_string())
}

/// Serialize a sequence of BabyJubJub Fq elements as an array of decimal strings.
///
/// Each Fq element is serialized as a decimal string.
pub fn serialize_babyjubjub_fq_sequence<S: Serializer>(
    ps: &[taceo_ark_babyjubjub::Fq],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        seq.serialize_element(&p.to_string())?;
    }
    seq.end()
}

/// Deserialize a BabyJubJub affine point from an array of two coordinate strings.
///
/// The EdwardsAffine point is deserialized from `[x, y]` format. Validates that the
/// point is on the curve and in the correct subgroup.
pub fn deserialize_babyjubjub_affine<'de, D>(
    deserializer: D,
) -> Result<taceo_ark_babyjubjub::EdwardsAffine, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(BabyJubJubAffineVisitor)
}

/// Deserialize a sequence of BabyJubJub affine points from an array of coordinate pair arrays.
///
/// Each EdwardsAffine point is deserialized from `[x, y]` format. Validates that all points
/// are on the curve and in the correct subgroup.
pub fn deserialize_babyjubjub_affine_sequence<'de, D>(
    deserializer: D,
) -> Result<Vec<taceo_ark_babyjubjub::EdwardsAffine>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(BabyJubJubAffineSeqVisitor { size: None })
}

/// Deserialize a BabyJubJub Fr (scalar field) element from a decimal string.
///
/// The Fr field element is deserialized from its decimal string representation.
pub fn deserialize_babyjubjub_fr<'de, D>(
    deserializer: D,
) -> Result<taceo_ark_babyjubjub::Fr, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_str(BabyJubJubFrVisitor)
}

/// Deserialize a BabyJubJub Fq (base field) element from a decimal string.
///
/// The Fq field element is deserialized from its decimal string representation.
pub fn deserialize_babyjubjub_fq<'de, D>(
    deserializer: D,
) -> Result<taceo_ark_babyjubjub::Fq, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_str(BabyJubJubFqVisitor)
}

/// Deserialize a sequence of BabyJubJub Fq elements from an array of decimal strings.
///
/// Each Fq element is deserialized from its decimal string representation.
pub fn deserialize_babyjubjub_fq_sequence<'de, D>(
    deserializer: D,
) -> Result<Vec<taceo_ark_babyjubjub::Fq>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(BabyJubJubFqSeqVisitor)
}

fn babyjubjub_affine_from_strings(
    x: &str,
    y: &str,
) -> Result<taceo_ark_babyjubjub::EdwardsAffine, SerdeCompatError> {
    let x = taceo_ark_babyjubjub::Fq::from_str(x).map_err(|_| SerdeCompatError)?;
    let y = taceo_ark_babyjubjub::Fq::from_str(y).map_err(|_| SerdeCompatError)?;
    let p = taceo_ark_babyjubjub::EdwardsAffine::new_unchecked(x, y);
    if p.is_zero() {
        return Ok(p);
    }
    if !p.is_on_curve() {
        return Err(SerdeCompatError);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerdeCompatError);
    }
    Ok(p)
}

struct BabyJubJubAffineVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubAffineVisitor {
    type Value = taceo_ark_babyjubjub::EdwardsAffine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 2 strings, representing a affine babyjubjub point")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected babyjubjub affine coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected babyjubjub affine coordinates but y coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(3, &self))
        } else {
            babyjubjub_affine_from_strings(&x, &y)
                .map_err(|_| de::Error::custom("Invalid affine point on babyjubjub.".to_owned()))
        }
    }
}

struct BabyJubJubFrVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubFrVisitor {
    type Value = taceo_ark_babyjubjub::Fr;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sting representing a babyjubjub Fr element")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        taceo_ark_babyjubjub::Fr::from_str(v).map_err(|_| E::custom("Invalid data"))
    }
}

struct BabyJubJubFqVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubFqVisitor {
    type Value = taceo_ark_babyjubjub::Fq;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sting representing a babyjubjub Fq point")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        taceo_ark_babyjubjub::Fq::from_str(v).map_err(|_| E::custom("Invalid data"))
    }
}

struct BabyJubJubFqSeqVisitor;

impl<'de> de::Visitor<'de> for BabyJubJubFqSeqVisitor {
    type Value = Vec<taceo_ark_babyjubjub::Fq>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of elements representing babyjubjub Fq points.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(v) = seq.next_element::<String>()? {
            values.push(
                taceo_ark_babyjubjub::Fq::from_str(&v)
                    .map_err(|_| de::Error::custom("Invalid data"))?,
            );
        }
        Ok(values)
    }
}

struct BabyJubJubAffineSeqVisitor {
    size: Option<usize>,
}

impl<'de> de::Visitor<'de> for BabyJubJubAffineSeqVisitor {
    type Value = Vec<taceo_ark_babyjubjub::EdwardsAffine>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(size) = self.size {
            formatter.write_str(&format!(
                "a sequence of elements representing babyjubjub affine points of length {size}."
            ))
        } else {
            formatter.write_str(
                "a sequence of elements representing babyjubjub affine points of variable length.",
            )
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(point) = seq.next_element::<Vec<String>>()? {
            //check if there are no more elements
            if point.len() != 2 {
                return Err(de::Error::invalid_length(point.len(), &self));
            } else {
                values.push(
                    babyjubjub_affine_from_strings(&point[0], &point[1]).map_err(|_| {
                        de::Error::custom("Invalid affine point on babyjubjub.".to_owned())
                    })?,
                );
            }
        }
        if self.size.is_some_and(|size| size != values.len()) {
            Err(de::Error::invalid_length(values.len(), &self))
        } else {
            Ok(values)
        }
    }
}
