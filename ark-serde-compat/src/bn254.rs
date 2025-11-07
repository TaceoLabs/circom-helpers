//! Serialization and deserialization functions for BN254 curve types.
//!
//! This module provides serde-compatible serialization and deserialization functions
//! for BN254 curve types, including field elements (Fr, Fq), curve points (G1, G2),
//! and target group elements (GT/Fq12).
//!
//! All field elements are serialized as decimal strings. Curve points are serialized
//! in projective coordinates as arrays of strings.

use ark_ec::{AffineRepr as _, CurveGroup as _};
use serde::{Serializer, de, ser::SerializeSeq as _};
use std::str::FromStr;

use crate::SerdeCompatError;

/// Serialize a BN254 Fr (scalar field) element as a decimal string.
///
/// The Fr field element is serialized to its decimal string representation.
pub fn serialize_fr<S: Serializer>(f: &ark_bn254::Fr, ser: S) -> Result<S::Ok, S::Error> {
    super::serialize_f(f, ser)
}

/// Serialize a BN254 Fq (base field) element as a decimal string.
///
/// The Fq field element is serialized to its decimal string representation.
pub fn serialize_fq<S: Serializer>(f: &ark_bn254::Fq, ser: S) -> Result<S::Ok, S::Error> {
    super::serialize_f(f, ser)
}

/// Serialize a BN254 G1 point as an array of three coordinate strings.
///
/// The G1 point is serialized in projective coordinates as `[x, y, z]` where each
/// coordinate is a decimal string. The point at infinity is represented as `["0", "1", "0"]`.
pub fn serialize_g1<S: Serializer>(p: &ark_bn254::G1Affine, ser: S) -> Result<S::Ok, S::Error> {
    let strings = g1_to_strings_projective(p);
    let mut seq = ser.serialize_seq(Some(strings.len()))?;
    for ele in strings {
        seq.serialize_element(&ele)?;
    }
    seq.end()
}

/// Serialize a BN254 G2 point as a 3x2 array of coordinate strings.
///
/// The G2 point is serialized in projective coordinates as `[[x0, x1], [y0, y1], [z0, z1]]`
/// where each coordinate is a pair of decimal strings representing an Fq2 element.
pub fn serialize_g2<S: Serializer>(p: &ark_bn254::G2Affine, ser: S) -> Result<S::Ok, S::Error> {
    let (x, y) = (p.x, p.y);
    let mut x_seq = ser.serialize_seq(Some(3))?;
    x_seq.serialize_element(&[x.c0.to_string(), x.c1.to_string()])?;
    x_seq.serialize_element(&[y.c0.to_string(), y.c1.to_string()])?;
    x_seq.serialize_element(&["1", "0"])?;
    x_seq.end()
}

/// Serialize a BN254 GT (target group) element as a 2x3x2 array of strings.
///
/// The Fq12 element is serialized as `[[[String; 2]; 3], [[String; 2]; 3]]` representing
/// the two Fq6 components, each with three Fq2 components.
pub fn serialize_gt<S: Serializer>(p: &ark_bn254::Fq12, ser: S) -> Result<S::Ok, S::Error> {
    let a = p.c0;
    let b = p.c1;
    let aa = a.c0;
    let ab = a.c1;
    let ac = a.c2;
    let ba = b.c0;
    let bb = b.c1;
    let bc = b.c2;
    let a = [
        [aa.c0.to_string(), aa.c1.to_string()],
        [ab.c0.to_string(), ab.c1.to_string()],
        [ac.c0.to_string(), ac.c1.to_string()],
    ];
    let b = [
        [ba.c0.to_string(), ba.c1.to_string()],
        [bb.c0.to_string(), bb.c1.to_string()],
        [bc.c0.to_string(), bc.c1.to_string()],
    ];
    let mut seq = ser.serialize_seq(Some(2))?;
    seq.serialize_element(&a)?;
    seq.serialize_element(&b)?;
    seq.end()
}

/// Serialize a sequence of BN254 G1 points as an array of projective coordinate arrays.
///
/// Each G1 point is serialized as `[x, y, z]` where each coordinate is a decimal string.
pub fn serialize_g1_sequence<S: Serializer>(
    ps: &[ark_bn254::G1Affine],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        seq.serialize_element(&g1_to_strings_projective(p))?;
    }
    seq.end()
}

fn g1_to_strings_projective(p: &ark_bn254::G1Affine) -> [String; 3] {
    if let Some((x, y)) = p.xy() {
        [x.to_string(), y.to_string(), "1".to_owned()]
    } else {
        //point at infinity
        ["0".to_owned(), "1".to_owned(), "0".to_owned()]
    }
}

struct Bn254G1Visitor;
struct Bn254G2Visitor;
struct Bn254GtVisitor;
struct Bn254G1SeqVisitor;

/// Deserialize a BN254 Fr (scalar field) element from a decimal string.
///
/// The Fr field element is deserialized from its decimal string representation.
pub fn deserialize_fr<'de, D>(deserializer: D) -> Result<ark_bn254::Fr, D::Error>
where
    D: de::Deserializer<'de>,
{
    super::deserialize_f(deserializer)
}

/// Deserialize a BN254 Fq (base field) element from a decimal string.
///
/// The Fq field element is deserialized from its decimal string representation.
pub fn deserialize_fq<'de, D>(deserializer: D) -> Result<ark_bn254::Fq, D::Error>
where
    D: de::Deserializer<'de>,
{
    super::deserialize_f(deserializer)
}

/// Deserialize a BN254 G1 point from an array of three coordinate strings.
///
/// The G1 point is deserialized from projective coordinates `[x, y, z]` where each
/// coordinate is a decimal string. Validates that the point is on the curve and in
/// the correct subgroup.
pub fn deserialize_g1<'de, D>(deserializer: D) -> Result<ark_bn254::G1Affine, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254G1Visitor)
}

/// Deserialize a BN254 G2 point from a 3x2 array of coordinate strings.
///
/// The G2 point is deserialized from projective coordinates `[[x0, x1], [y0, y1], [z0, z1]]`
/// where each coordinate pair represents an Fq2 element. Validates that the point is on
/// the curve and in the correct subgroup.
pub fn deserialize_g2<'de, D>(deserializer: D) -> Result<ark_bn254::G2Affine, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254G2Visitor)
}

/// Deserialize a BN254 GT (target group) element from a 2x3x2 array of strings.
///
/// The Fq12 element is deserialized from `[[[String; 2]; 3], [[String; 2]; 3]]` format.
pub fn deserialize_gt<'de, D>(deserializer: D) -> Result<ark_bn254::Fq12, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254GtVisitor)
}

/// Deserialize a sequence of BN254 G1 points from an array of projective coordinate arrays.
///
/// Each G1 point is deserialized from `[x, y, z]` format. Validates that all points are
/// on the curve and in the correct subgroup.
pub fn deserialize_g1_sequence<'de, D>(
    deserializer: D,
) -> Result<Vec<ark_bn254::G1Affine>, D::Error>
where
    D: de::Deserializer<'de>,
{
    deserializer.deserialize_seq(Bn254G1SeqVisitor)
}

fn g1_from_strings_projective(
    x: &str,
    y: &str,
    z: &str,
) -> Result<ark_bn254::G1Affine, SerdeCompatError> {
    let x = ark_bn254::Fq::from_str(x).map_err(|_| SerdeCompatError)?;
    let y = ark_bn254::Fq::from_str(y).map_err(|_| SerdeCompatError)?;
    let z = ark_bn254::Fq::from_str(z).map_err(|_| SerdeCompatError)?;
    let p = ark_bn254::G1Projective::new_unchecked(x, y, z).into_affine();
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

fn g2_from_strings_projective(
    x0: &str,
    x1: &str,
    y0: &str,
    y1: &str,
    z0: &str,
    z1: &str,
) -> Result<ark_bn254::G2Affine, SerdeCompatError> {
    let x0 = ark_bn254::Fq::from_str(x0).map_err(|_| SerdeCompatError)?;
    let x1 = ark_bn254::Fq::from_str(x1).map_err(|_| SerdeCompatError)?;
    let y0 = ark_bn254::Fq::from_str(y0).map_err(|_| SerdeCompatError)?;
    let y1 = ark_bn254::Fq::from_str(y1).map_err(|_| SerdeCompatError)?;
    let z0 = ark_bn254::Fq::from_str(z0).map_err(|_| SerdeCompatError)?;
    let z1 = ark_bn254::Fq::from_str(z1).map_err(|_| SerdeCompatError)?;

    let x = ark_bn254::Fq2::new(x0, x1);
    let y = ark_bn254::Fq2::new(y0, y1);
    let z = ark_bn254::Fq2::new(z0, z1);
    let p = ark_bn254::G2Projective::new_unchecked(x, y, z).into_affine();
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

impl<'de> de::Visitor<'de> for Bn254G1Visitor {
    type Value = ark_bn254::G1Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of 3 strings, representing a projective point on G1")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<String>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else {
            g1_from_strings_projective(&x, &y, &z)
                .map_err(|_| de::Error::custom("Invalid projective point on G1.".to_owned()))
        }
    }
}

impl<'de> de::Visitor<'de> for Bn254G2Visitor {
    type Value = ark_bn254::G2Affine;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter
            .write_str("a sequence of 3 sequences, representing a projective point on G2. The 3 sequences each consist of two strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G1 projective coordinates but x coordinate missing.".to_owned(),
        ))?;
        let y = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but y coordinate missing.".to_owned(),
        ))?;
        let z = seq.next_element::<Vec<String>>()?.ok_or(de::Error::custom(
            "expected G2 projective coordinates but z coordinate missing.".to_owned(),
        ))?;
        //check if there are no more elements
        if seq.next_element::<String>()?.is_some() {
            Err(de::Error::invalid_length(4, &self))
        } else if x.len() != 2 {
            Err(de::Error::custom(format!(
                "x coordinates need two field elements for G2, but got {}",
                x.len()
            )))
        } else if y.len() != 2 {
            Err(de::Error::custom(format!(
                "y coordinates need two field elements for G2, but got {}",
                y.len()
            )))
        } else if z.len() != 2 {
            Err(de::Error::custom(format!(
                "z coordinates need two field elements for G2, but got {}",
                z.len()
            )))
        } else {
            g2_from_strings_projective(&x[0], &x[1], &y[0], &y[1], &z[0], &z[1])
                .map_err(|_| de::Error::custom("Invalid projective point on G2.".to_owned()))
        }
    }
}

impl<'de> de::Visitor<'de> for Bn254GtVisitor {
    type Value = ark_bn254::Fq12;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(
                "An element of Fq12 represented as string with radix 10. Must be a sequence of form [[[String; 2]; 3]; 2]."
            )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let x = seq
            .next_element::<Vec<Vec<String>>>()?
            .ok_or(de::Error::custom(
                "expected elements target group in {} as sequence of sequences",
            ))?;
        let y = seq
            .next_element::<Vec<Vec<String>>>()?
            .ok_or(de::Error::custom(
                "expected elements target group in {} as sequence of sequences",
            ))?;
        if x.len() != 3 || y.len() != 3 {
            Err(de::Error::custom(
                "need three elements for cubic extension field in {}",
            ))
        } else {
            let c0 = cubic_extension_field_from_vec(x).map_err(|_| {
                de::Error::custom("InvalidData for target group (cubic extension field)")
            })?;
            let c1 = cubic_extension_field_from_vec(y).map_err(|_| {
                de::Error::custom("InvalidData for target group (cubic extension field)")
            })?;
            Ok(ark_bn254::Fq12::new(c0, c1))
        }
    }
}

#[inline]
fn cubic_extension_field_from_vec(
    strings: Vec<Vec<String>>,
) -> Result<ark_bn254::Fq6, SerdeCompatError> {
    if strings.len() != 3 {
        Err(SerdeCompatError)
    } else {
        let c0 = quadratic_extension_field_from_vec(&strings[0])?;
        let c1 = quadratic_extension_field_from_vec(&strings[1])?;
        let c2 = quadratic_extension_field_from_vec(&strings[2])?;
        Ok(ark_bn254::Fq6::new(c0, c1, c2))
    }
}

#[inline]
fn quadratic_extension_field_from_vec(
    strings: &[String],
) -> Result<ark_bn254::Fq2, SerdeCompatError> {
    if strings.len() != 2 {
        Err(SerdeCompatError)
    } else {
        let c0 = ark_bn254::Fq::from_str(&strings[0]).map_err(|_| SerdeCompatError)?;
        let c1 = ark_bn254::Fq::from_str(&strings[1]).map_err(|_| SerdeCompatError)?;
        Ok(ark_bn254::Fq2::new(c0, c1))
    }
}

impl<'de> de::Visitor<'de> for Bn254G1SeqVisitor {
    type Value = Vec<ark_bn254::G1Affine>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(
            "a sequence of elements representing projective points on G1, which in turn are sequences of three elements on the BaseField of the Curve.",
        )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(point) = seq.next_element::<Vec<String>>()? {
            //check if there are no more elements
            if point.len() != 3 {
                return Err(de::Error::invalid_length(point.len(), &self));
            } else {
                values.push(
                    g1_from_strings_projective(&point[0], &point[1], &point[2]).map_err(|_| {
                        de::Error::custom("Invalid projective point on G1.".to_owned())
                    })?,
                );
            }
        }
        Ok(values)
    }
}
