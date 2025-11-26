//! Serialization and deserialization functions for BabyJubJub curve types.
//!
//! This module provides serde-compatible serialization and deserialization functions
//! for BabyJubJub curve types, including field elements (Fr, Fq) and curve points
//! (EdwardsAffine).
//!
//! All field elements are serialized as decimal strings. Curve points are serialized
//! in affine coordinates as arrays of two coordinate strings.

use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _, Compress};
use serde::ser::Error;
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
pub fn serialize_fr<S: Serializer>(f: &ark_babyjubjub::Fr, ser: S) -> Result<S::Ok, S::Error> {
    super::serialize_f(f, ser)
}

/// Serialize a BabyJubJub Fq (base field) element as a decimal string.
///
/// The Fq field element is serialized to its decimal string representation.
pub fn serialize_fq<S: Serializer>(f: &ark_babyjubjub::Fq, ser: S) -> Result<S::Ok, S::Error> {
    super::serialize_f(f, ser)
}

/// Serialize a sequence of BabyJubJub Fq elements as an array of decimal strings.
///
/// Each Fq element is serialized as a decimal string.
pub fn serialize_fq_seq<S: Serializer>(
    ps: &[ark_babyjubjub::Fq],
    ser: S,
) -> Result<S::Ok, S::Error> {
    super::serialize_f_seq(ps, ser)
}

/// Serialize a BabyJubJub affine point as an array of two coordinate strings.
///
/// The EdwardsAffine point is serialized as `[x, y]` where each coordinate
/// is a decimal string representing an Fq element.
pub fn serialize_affine<S: Serializer>(
    p: &ark_babyjubjub::EdwardsAffine,
    ser: S,
) -> Result<S::Ok, S::Error> {
    if ser.is_human_readable() {
        let (x, y) = (p.x, p.y);
        let mut x_seq = ser.serialize_seq(Some(2))?;
        x_seq.serialize_element(&x.to_string())?;
        x_seq.serialize_element(&y.to_string())?;
        x_seq.end()
    } else {
        let mut bytes = Vec::with_capacity(p.serialized_size(Compress::Yes));
        p.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Serialize a sequence of BabyJubJub affine points as an array of coordinate pair arrays.
///
/// Each EdwardsAffine point is serialized as `[x, y]` where each coordinate is a decimal string.
pub fn serialize_affine_seq<S: Serializer>(
    ps: &[ark_babyjubjub::EdwardsAffine],
    ser: S,
) -> Result<S::Ok, S::Error> {
    if ser.is_human_readable() {
        let mut seq = ser.serialize_seq(Some(ps.len()))?;
        for p in ps {
            let (x, y) = (p.x, p.y);
            seq.serialize_element(&[x.to_string(), y.to_string()])?;
        }
        seq.end()
    } else {
        let mut bytes = Vec::with_capacity(ps.serialized_size(Compress::Yes));
        ps.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Deserialize a BabyJubJub Fr (scalar field) element from a decimal string.
///
/// The Fr field element is deserialized from its decimal string representation.
pub fn deserialize_fr<'de, D>(deserializer: D) -> Result<ark_babyjubjub::Fr, D::Error>
where
    D: de::Deserializer<'de>,
{
    super::deserialize_f(deserializer)
}

/// Deserialize a BabyJubJub Fq (base field) element from a decimal string.
///
/// The Fq field element is deserialized from its decimal string representation.
pub fn deserialize_fq<'de, D>(deserializer: D) -> Result<ark_babyjubjub::Fq, D::Error>
where
    D: de::Deserializer<'de>,
{
    super::deserialize_f(deserializer)
}

/// Deserialize a sequence of BabyJubJub Fq elements from an array of decimal strings.
///
/// Each Fq element is deserialized from its decimal string representation.
pub fn deserialize_fq_seq<'de, D>(deserializer: D) -> Result<Vec<ark_babyjubjub::Fq>, D::Error>
where
    D: de::Deserializer<'de>,
{
    super::deserialize_f_seq(deserializer)
}

/// Deserialize a BabyJubJub affine point from an array of two coordinate strings.
///
/// The EdwardsAffine point is deserialized from `[x, y]` format. Validates that the
/// point is on the curve and in the correct subgroup.
pub fn deserialize_affine<'de, D>(
    deserializer: D,
) -> Result<ark_babyjubjub::EdwardsAffine, D::Error>
where
    D: de::Deserializer<'de>,
{
    let visitor = BabyJubJubAffineVisitor::<true>;
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a BabyJubJub affine point from an array of two coordinate strings without validation.
///
/// The EdwardsAffine point is deserialized from `[x, y]` format. **Does not** validate that the
/// point is on the curve or in the correct subgroup, making it significantly faster but potentially
/// unsafe. Use only with trusted input.
pub fn deserialize_affine_unchecked<'de, D>(
    deserializer: D,
) -> Result<ark_babyjubjub::EdwardsAffine, D::Error>
where
    D: de::Deserializer<'de>,
{
    let visitor = BabyJubJubAffineVisitor::<false>;
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a sequence of BabyJubJub affine points from an array of coordinate pair arrays.
///
/// Each EdwardsAffine point is deserialized from `[x, y]` format. Validates that all points
/// are on the curve and in the correct subgroup.
pub fn deserialize_affine_seq<'de, D>(
    deserializer: D,
) -> Result<Vec<ark_babyjubjub::EdwardsAffine>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let visitor = BabyJubJubAffineSeqVisitor::<true> { size: None };
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a sequence of BabyJubJub affine points from an array of coordinate pair arrays without validation.
///
/// Each EdwardsAffine point is deserialized from `[x, y]` format. **Does not** validate that the
/// points are on the curve or in the correct subgroup, making it significantly faster but potentially
/// unsafe. Use only with trusted input.
pub fn deserialize_affine_seq_unchecked<'de, D>(
    deserializer: D,
) -> Result<Vec<ark_babyjubjub::EdwardsAffine>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let visitor = BabyJubJubAffineSeqVisitor::<false> { size: None };
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize am array of BabyJubJub affine points from an array of coordinate pair arrays.
///
/// Each EdwardsAffine point is deserialized from `[x, y]` format. Validates that all points
/// are on the curve and in the correct subgroup. Returns an error if not exactly `LENGTH` elements
/// can be deserialized.
pub fn deserialize_affine_array<'de, const LENGTH: usize, D>(
    deserializer: D,
) -> Result<[ark_babyjubjub::EdwardsAffine; LENGTH], D::Error>
where
    D: de::Deserializer<'de>,
{
    let visitor = BabyJubJubAffineSeqVisitor::<true> { size: Some(LENGTH) };
    let result = if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)?
    } else {
        deserializer.deserialize_bytes(visitor)?
    }
    .try_into()
    .expect("Works if not an error");
    Ok(result)
}

/// Deserialize am array of BabyJubJub affine points from an array of coordinate pair arrays.
///
/// Each EdwardsAffine point is deserialized from `[x, y]` format. **Does not** validate that the
/// points are on the curve or in the correct subgroup, making it significantly faster but potentially
/// unsafe. Use only with trusted input. Returns an error if not exactly `LENGTH` elements
/// can be deserialized.
pub fn deserialize_affine_array_unchecked<'de, const LENGTH: usize, D>(
    deserializer: D,
) -> Result<[ark_babyjubjub::EdwardsAffine; LENGTH], D::Error>
where
    D: de::Deserializer<'de>,
{
    let visitor = BabyJubJubAffineSeqVisitor::<false> { size: Some(LENGTH) };
    let result = if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)?
    } else {
        deserializer.deserialize_bytes(visitor)?
    }
    .try_into()
    .expect("Works if not an error");
    Ok(result)
}

fn affine_from_strings<const CHECK: bool>(
    x: &str,
    y: &str,
) -> Result<ark_babyjubjub::EdwardsAffine, SerdeCompatError> {
    let x = ark_babyjubjub::Fq::from_str(x).map_err(|_| SerdeCompatError)?;
    let y = ark_babyjubjub::Fq::from_str(y).map_err(|_| SerdeCompatError)?;
    let p = ark_babyjubjub::EdwardsAffine::new_unchecked(x, y);
    if p.is_zero() {
        return Ok(p);
    }
    if CHECK {
        if !p.is_on_curve() {
            return Err(SerdeCompatError);
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(SerdeCompatError);
        }
    }
    Ok(p)
}

struct BabyJubJubAffineVisitor<const CHECK: bool>;
struct BabyJubJubAffineSeqVisitor<const CHECK: bool> {
    size: Option<usize>,
}

impl<'de, const CHECK: bool> de::Visitor<'de> for BabyJubJubAffineVisitor<CHECK> {
    type Value = ark_babyjubjub::EdwardsAffine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 2 strings, representing a affine babyjubjub point")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if CHECK {
            Self::Value::deserialize_compressed(v)
        } else {
            Self::Value::deserialize_compressed_unchecked(v)
        }
        .map_err(|err| de::Error::custom(err.to_string()))
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
            affine_from_strings::<CHECK>(&x, &y)
                .map_err(|_| de::Error::custom("Invalid affine point on babyjubjub.".to_owned()))
        }
    }
}

impl<'de, const CHECK: bool> de::Visitor<'de> for BabyJubJubAffineSeqVisitor<CHECK> {
    type Value = Vec<ark_babyjubjub::EdwardsAffine>;

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

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if CHECK {
            Self::Value::deserialize_compressed(v)
        } else {
            Self::Value::deserialize_compressed_unchecked(v)
        }
        .map_err(|err| de::Error::custom(err.to_string()))
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
                    affine_from_strings::<CHECK>(&point[0], &point[1]).map_err(|_| {
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
