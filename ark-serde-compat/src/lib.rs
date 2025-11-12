//! # ark-serde-compat
//!
//! Various serde compatibility implementations for arkworks-rs types, including serializing
//! to strings for use in human-readable JSON. The design choices are heavily influenced to
//! work with circom.
//!
//! This crate provides serialization and deserialization functions for arkworks types that
//! are compatible with circom's expected JSON format. Field elements are serialized as
//! decimal strings, and curve points are serialized as arrays of coordinate strings.
//!
//! ## Features
//!
//! - `bn254`: Enables serialization support for BN254 curve types
//! - `bls12-381`: Enables serialization support for BLS12-381 curve types
//! - `babyjubjub`: Enables serialization support for BabyJubJub curve types
//!
//! ## Usage
//!
//! Use the provided functions with serde's field attributes:
//!
//! ```ignore
//! use serde::{Serialize, Deserialize};
//! use ark_bn254::Fr;
//!
//! #[derive(Serialize, Deserialize)]
//! struct MyStruct {
//!     #[serde(serialize_with = "taceo_ark_serde_compat::serialize_f")]
//!     #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f")]
//!     field: Fr,
//! }
//! ```
//!
//! For curve-specific helpers, use the appropriate module:
//!
//! ```ignore
//! use serde::{Serialize, Deserialize};
//! use ark_bn254::G1Affine;
//!
//! #[derive(Serialize, Deserialize)]
//! struct MyStruct {
//!     #[serde(serialize_with = "taceo_ark_serde_compat::bn254::serialize_g1")]
//!     #[serde(deserialize_with = "taceo_ark_serde_compat::bn254::deserialize_g1")]
//!     point: G1Affine,
//! }
//! ```

#![deny(missing_docs)]
use std::marker::PhantomData;

use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{
    CubicExtConfig, CubicExtField, Field, Fp12Config, Fp12ConfigWrapper, PrimeField, QuadExtConfig,
    QuadExtField, Zero,
};
use serde::{Serializer, de, ser::SerializeSeq as _};

#[cfg(any(feature = "bn254", feature = "bls12-381"))]
mod impl_macro;

/// Trait providing canonical JSON serialization for pairing-friendly elliptic curves.
///
/// This trait defines a standard interface for serializing and deserializing pairing curve
/// elements (G1, G2, GT) to and from human-readable JSON formats. It is implemented for
/// specific pairing curves like BN254 and BLS12-381.
///
/// The serialization format uses decimal strings for field elements and arrays of strings
/// for group elements to ensure compatibility with circom and other tools.
pub trait CanonicalJsonSerialize: Pairing {
    /// Serializes a G1 affine point as an array of coordinate strings.
    fn serialize_g1<S: Serializer>(p: &Self::G1Affine, ser: S) -> Result<S::Ok, S::Error>;

    /// Serializes a G2 affine point as an array of coordinate strings.
    fn serialize_g2<S: Serializer>(p: &Self::G2Affine, ser: S) -> Result<S::Ok, S::Error>;
    
    /// Serializes a target group (GT) element as an array of coordinate strings.
    fn serialize_gt<S: Serializer>(p: &Self::TargetField, ser: S) -> Result<S::Ok, S::Error>;
    
    /// Serializes a sequence of G1 affine points as an array of coordinate arrays.
    fn serialize_g1_seq<S: Serializer>(p: &[Self::G1Affine], ser: S) -> Result<S::Ok, S::Error>;

    /// Deserializes a G1 affine point from coordinate strings with full validation.
    fn deserialize_g1<'de, D>(deserializer: D) -> Result<Self::G1Affine, D::Error>
    where
        D: de::Deserializer<'de>;

    /// Deserializes a G1 affine point from coordinate strings without validation checks.
    ///
    /// # Safety
    ///
    /// This skips curve and subgroup checks. Only use with trusted input.
    fn deserialize_g1_unchecked<'de, D>(deserializer: D) -> Result<Self::G1Affine, D::Error>
    where
        D: de::Deserializer<'de>;

    /// Deserializes a G2 affine point from coordinate strings with full validation.
    fn deserialize_g2<'de, D>(deserializer: D) -> Result<Self::G2Affine, D::Error>
    where
        D: de::Deserializer<'de>;

    /// Deserializes a G2 affine point from coordinate strings without validation checks.
    ///
    /// # Safety
    ///
    /// This skips curve and subgroup checks. Only use with trusted input.
    fn deserialize_g2_unchecked<'de, D>(deserializer: D) -> Result<Self::G2Affine, D::Error>
    where
        D: de::Deserializer<'de>;

    /// Deserializes a target group (GT) element from coordinate strings.
    fn deserialize_gt<'de, D>(deserializer: D) -> Result<Self::TargetField, D::Error>
    where
        D: de::Deserializer<'de>;

    /// Deserializes a sequence of G1 affine points from coordinate arrays with full validation.
    fn deserialize_g1_seq<'de, D>(deserializer: D) -> Result<Vec<Self::G1Affine>, D::Error>
    where
        D: de::Deserializer<'de>;

    /// Deserializes a sequence of G1 affine points from coordinate arrays without validation checks.
    ///
    /// # Safety
    ///
    /// This skips curve and subgroup checks for all points. Only use with trusted input.
    fn deserialize_g1_seq_unchecked<'de, D>(
        deserializer: D,
    ) -> Result<Vec<Self::G1Affine>, D::Error>
    where
        D: de::Deserializer<'de>;
}

// Silence the error in case we use no features
#[allow(unused)]
pub(crate) struct SerdeCompatError;

/// Indicates whether we should check if deserialized are valid
/// points on the curves.
/// `No` indicates to skip those checks, which is by orders of magnitude
/// faster, but could potentially result in undefined behaviour. Use
/// only with care.
#[derive(Debug, Clone, Copy)]
pub enum CheckElement {
    /// Indicates to perform curve checks
    Yes,
    /// Indicates to skip curve checks
    No,
}

/// Serialize a prime field element as a decimal string.
///
/// This function serializes any arkworks prime field element to its decimal string
/// representation for use in JSON and other human-readable formats.
///
/// # Example
///
/// ```ignore
/// use serde::Serialize;
/// use ark_bn254::Fr;
///
/// #[derive(Serialize)]
/// struct MyStruct {
///     #[serde(serialize_with = "taceo_ark_serde_compat::serialize_f")]
///     field: Fr,
/// }
/// ```
pub fn serialize_f<S: Serializer>(p: &impl PrimeField, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&p.to_string())
}

/// Serialize a sequence of prime field elements as an array of decimal strings.
///
/// This function serializes a slice of arkworks prime field elements to an array where
/// each element is represented as its decimal string.
///
/// # Example
///
/// ```ignore
/// use serde::Serialize;
/// use ark_bn254::Fr;
///
/// #[derive(Serialize)]
/// struct MyStruct {
///     #[serde(serialize_with = "taceo_ark_serde_compat::serialize_f_seq")]
///     fields: Vec<Fr>,
/// }
/// ```
pub fn serialize_f_seq<S: Serializer, F: PrimeField>(ps: &[F], ser: S) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        seq.serialize_element(&p.to_string())?;
    }
    seq.end()
}

/// Deserialize a prime field element from a decimal string.
///
/// This function deserializes a prime field element from its decimal string
/// representation.
///
/// # Example
///
/// ```ignore
/// use serde::Deserialize;
/// use ark_bn254::Fr;
///
/// #[derive(Deserialize)]
/// struct MyStruct {
///     #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f")]
///     field: Fr,
/// }
/// ```
pub fn deserialize_f<'de, F, D>(deserializer: D) -> Result<F, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
{
    deserializer.deserialize_str(PrimeFieldVisitor::<F>::default())
}

/// Deserialize a sequence of prime field elements from an array of decimal strings.
///
/// This function deserializes an array of decimal strings into a vector of prime field
/// elements.
///
/// # Example
///
/// ```ignore
/// use serde::Deserialize;
/// use ark_bn254::Fr;
///
/// #[derive(Deserialize)]
/// struct MyStruct {
///     #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f_seq")]
///     fields: Vec<Fr>,
/// }
/// ```
pub fn deserialize_f_seq<'de, D, F>(deserializer: D) -> Result<Vec<F>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
{
    deserializer.deserialize_seq(PrimeFieldSeqVisitor::<F> {
        phantom_data: PhantomData,
    })
}

/// Serialize a G1 affine point as an array of three coordinate strings.
///
/// This function serializes an elliptic curve point in G1 to projective coordinates
/// `[x, y, z]` as decimal strings. The point at infinity is represented as `["0", "1", "0"]`.
///
/// This is a generic function that works with any curve implementing `AffineRepr`.
/// For curve-specific helpers, see the module functions like `bn254::serialize_g1`.
pub fn serialize_g1<S: Serializer, F: Field>(
    p: &impl AffineRepr<BaseField = F>,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let strings = g1_to_strings_projective(p);
    let mut seq = ser.serialize_seq(Some(strings.len()))?;
    for ele in strings {
        seq.serialize_element(&ele)?;
    }
    seq.end()
}

/// Serialize a G2 affine point as a 3×2 array of coordinate strings.
///
/// This function serializes an elliptic curve point in G2 to projective coordinates
/// `[[x0, x1], [y0, y1], [z0, z1]]` as decimal strings, where each coordinate is
/// represented as a quadratic extension field element (two components). The point at
/// infinity is represented as `[["0", "0"], ["1", "0"], ["0", "0"]]`.
///
/// This is a generic function that works with any curve implementing `AffineRepr` with
/// a quadratic extension base field. For curve-specific helpers, see the module functions
/// like `bn254::serialize_g2`.
pub fn serialize_g2<F, S: Serializer>(
    p: &impl AffineRepr<BaseField = QuadExtField<F>>,
    ser: S,
) -> Result<S::Ok, S::Error>
where
    F: QuadExtConfig,
{
    let mut x_seq = ser.serialize_seq(Some(3))?;
    let (x, y) = p
        .xy()
        .unwrap_or((QuadExtField::<F>::zero(), QuadExtField::<F>::zero()));
    x_seq.serialize_element(&[x.c0.to_string(), x.c1.to_string()])?;
    x_seq.serialize_element(&[y.c0.to_string(), y.c1.to_string()])?;
    x_seq.serialize_element(&["1", "0"])?;
    x_seq.end()
}

/// Serialize a target group (GT/Fq12) element as a 2×3×2 array of decimal strings.
///
/// This function serializes an Fq12 extension field element (typically from a pairing
/// operation) as a nested array structure. An Fq12 element is viewed as two Fq6
/// components, each containing three Fq2 components, where each Fq2 is a pair of
/// base field elements.
///
/// The resulting structure is `[[[a00, a01], [a10, a11], [a20, a21]], [[b00, b01], [b10, b11], [b20, b21]]]`,
/// where each innermost pair represents an Fq2 element as decimal strings.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::serialize_gt`.
pub fn serialize_gt<S: Serializer, T>(
    p: &QuadExtField<Fp12ConfigWrapper<T>>,
    ser: S,
) -> Result<S::Ok, S::Error>
where
    T: Fp12Config,
{
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

/// Serialize a sequence of G1 affine points as an array of projective coordinate arrays.
///
/// This function serializes a slice of G1 points where each point is represented as
/// `[x, y, z]` with decimal strings. The point at infinity is represented as `["0", "1", "0"]`.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::serialize_g1_seq`.
pub fn serialize_g1_seq<S: Serializer, F: PrimeField>(
    ps: &[impl AffineRepr<BaseField = F>],
    ser: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = ser.serialize_seq(Some(ps.len()))?;
    for p in ps {
        seq.serialize_element(&g1_to_strings_projective(p))?;
    }
    seq.end()
}

/// Converts a G1 affine point to projective coordinate strings.
///
/// Returns `[x, y, "1"]` for finite points and `["0", "1", "0"]` for the point at infinity.
fn g1_to_strings_projective(p: &impl AffineRepr) -> [String; 3] {
    if let Some((x, y)) = p.xy() {
        [x.to_string(), y.to_string(), "1".to_owned()]
    } else {
        //point at infinity
        ["0".to_owned(), "1".to_owned(), "0".to_owned()]
    }
}

#[derive(Default)]
pub(crate) struct PrimeFieldVisitor<F> {
    phantom_data: PhantomData<F>,
}

#[derive(Default)]
pub(crate) struct PrimeFieldSeqVisitor<F> {
    phantom_data: PhantomData<F>,
}

/// Deserialize a G1 affine point from projective coordinate strings with full validation.
///
/// This function deserializes a G1 point from `[x, y, z]` format as decimal strings.
/// Performs full validation including field element decoding, on-curve check, and
/// subgroup membership verification. The point at infinity must be `["0", "1", "0"]`.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_g1`.
///
/// # Errors
///
/// Returns an error if the coordinates are invalid, the point is not on the curve,
/// or the point is not in the correct subgroup.
pub fn deserialize_g1<'de, D, F, G1>(deserializer: D) -> Result<Affine<G1>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    deserializer.deserialize_seq(G1Visitor::<true, _, _>(PhantomData))
}

/// Deserialize a G1 affine point from projective coordinate strings without validation.
///
/// This function deserializes a G1 point from `[x, y, z]` format as decimal strings.
/// **Does not** perform validation checks (field canonical form, on-curve, subgroup membership),
/// making it significantly faster but potentially unsafe.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_g1_unchecked`.
///
/// # Safety
///
/// Only use this function with trusted input. Invalid points can lead to undefined
/// behavior or security vulnerabilities in downstream cryptographic operations.
pub fn deserialize_g1_unchecked<'de, D, F, G1>(deserializer: D) -> Result<Affine<G1>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    deserializer.deserialize_seq(G1Visitor::<false, _, _>(PhantomData))
}

/// Deserialize a G2 affine point from projective coordinate strings with full validation.
///
/// This function deserializes a G2 point from `[[x0, x1], [y0, y1], [z0, z1]]` format
/// as decimal strings. Performs full validation including field element decoding,
/// on-curve check, and subgroup membership verification.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_g2`.
///
/// # Errors
///
/// Returns an error if the coordinates are invalid, the point is not on the curve,
/// or the point is not in the correct subgroup.
pub fn deserialize_g2<'de, D, F, Q, G2>(deserializer: D) -> Result<Affine<G2>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    Q: QuadExtConfig<BaseField = F>,
    G2: SWCurveConfig<BaseField = QuadExtField<Q>>,
{
    deserializer.deserialize_seq(G2Visitor::<true, _, _, _>(PhantomData))
}

/// Deserialize a G2 affine point from projective coordinate strings without validation.
///
/// This function deserializes a G2 point from `[[x0, x1], [y0, y1], [z0, z1]]` format
/// as decimal strings. **Does not** perform validation checks (field canonical form,
/// on-curve, subgroup membership), making it significantly faster but potentially unsafe.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_g2_unchecked`.
///
/// # Safety
///
/// Only use this function with trusted input. Invalid points can lead to undefined
/// behavior or security vulnerabilities in downstream cryptographic operations.
pub fn deserialize_g2_unchecked<'de, D, F, Q, G2>(deserializer: D) -> Result<Affine<G2>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    Q: QuadExtConfig<BaseField = F>,
    G2: SWCurveConfig<BaseField = QuadExtField<Q>>,
{
    deserializer.deserialize_seq(G2Visitor::<false, _, _, _>(PhantomData))
}
/// Deserialize a target group (GT/Fq12) element from its 2×3×2 decimal string representation.
///
/// This function deserializes an Fq12 extension field element from the nested array
/// structure `[[[a00, a01], [a10, a11], [a20, a21]], [[b00, b01], [b10, b11], [b20, b21]]]`.
/// Performs full validation of all component field elements.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_gt`.
///
/// # Errors
///
/// Returns an error if the structure is invalid or any field element cannot be parsed.
pub fn deserialize_gt<'de, D, F, Fp2, Fp6, Fp12>(
    deserializer: D,
) -> Result<QuadExtField<Fp12>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    Fp2: QuadExtConfig<BaseField = F>,
    Fp6: CubicExtConfig<BaseField = QuadExtField<Fp2>>,
    Fp12: QuadExtConfig<BaseField = CubicExtField<Fp6>>,
{
    deserializer.deserialize_seq(GtVisitor(PhantomData))
}

/// Deserialize a sequence of G1 affine points from coordinate arrays with full validation.
///
/// This function deserializes an array of G1 points where each point is in `[x, y, z]`
/// projective format as decimal strings. Performs full validation for each point including
/// field element decoding, on-curve check, and subgroup membership verification.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_g1_seq`.
///
/// # Errors
///
/// Returns an error if any coordinate is invalid, any point is not on the curve,
/// or any point is not in the correct subgroup.
pub fn deserialize_g1_seq<'de, D, F, G1>(deserializer: D) -> Result<Vec<Affine<G1>>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    deserializer.deserialize_seq(G1SeqVisitor::<true, _, _>(PhantomData))
}

/// Deserialize a sequence of G1 affine points from coordinate arrays without validation.
///
/// This function deserializes an array of G1 points where each point is in `[x, y, z]`
/// projective format as decimal strings. **Does not** perform validation checks for any
/// point, making it significantly faster but potentially unsafe.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::deserialize_g1_seq_unchecked`.
///
/// # Safety
///
/// Only use this function with trusted input. Invalid points can lead to undefined
/// behavior or security vulnerabilities in downstream cryptographic operations.
pub fn deserialize_g1_seq_unchecked<'de, D, F, G1>(
    deserializer: D,
) -> Result<Vec<Affine<G1>>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    deserializer.deserialize_seq(G1SeqVisitor::<false, _, _>(PhantomData))
}

impl<'de, const CHECK: bool, G1, F> de::Visitor<'de> for G1Visitor<CHECK, F, G1>
where
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    type Value = Affine<G1>;

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
            g1_from_strings_projective::<CHECK, _, _>(&x, &y, &z)
                .map_err(|_| de::Error::custom("Invalid projective point on G1.".to_owned()))
        }
    }
}

impl<'de, const CHECK: bool, F, Q, G2> de::Visitor<'de> for G2Visitor<CHECK, F, Q, G2>
where
    F: PrimeField,
    Q: QuadExtConfig<BaseField = F>,
    G2: SWCurveConfig<BaseField = QuadExtField<Q>>,
{
    type Value = Affine<G2>;

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
            g2_from_strings_projective::<CHECK, _, _, _>(&x[0], &x[1], &y[0], &y[1], &z[0], &z[1])
                .map_err(|_| de::Error::custom("Invalid projective point on G2.".to_owned()))
        }
    }
}

/// Parses a G1 affine point from projective coordinate strings.
///
/// If `CHECK` is true, validates the point is on the curve and in the correct subgroup.
/// Always accepts the point at infinity without validation.
fn g1_from_strings_projective<const CHECK: bool, F, G1>(
    x: &str,
    y: &str,
    z: &str,
) -> Result<Affine<G1>, SerdeCompatError>
where
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    let x = F::from_str(x).map_err(|_| SerdeCompatError)?;
    let y = F::from_str(y).map_err(|_| SerdeCompatError)?;
    let z = F::from_str(z).map_err(|_| SerdeCompatError)?;
    let p = Projective::<G1>::new_unchecked(x, y, z).into_affine();
    if p.is_zero() {
        return Ok(p);
    }
    if CHECK && !p.is_on_curve() {
        return Err(SerdeCompatError);
    }
    if CHECK && !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerdeCompatError);
    }
    Ok(p)
}

/// Parses a G2 affine point from projective coordinate strings.
///
/// Takes six strings representing the components of three Fq2 coordinates (x, y, z).
/// If `CHECK` is true, validates the point is on the curve and in the correct subgroup.
/// Always accepts the point at infinity without validation.
fn g2_from_strings_projective<const CHECK: bool, F, Q, G2>(
    x0: &str,
    x1: &str,
    y0: &str,
    y1: &str,
    z0: &str,
    z1: &str,
) -> Result<Affine<G2>, SerdeCompatError>
where
    F: PrimeField,
    Q: QuadExtConfig<BaseField = F>,
    G2: SWCurveConfig<BaseField = QuadExtField<Q>>,
{
    let x0 = F::from_str(x0).map_err(|_| SerdeCompatError)?;
    let x1 = F::from_str(x1).map_err(|_| SerdeCompatError)?;
    let y0 = F::from_str(y0).map_err(|_| SerdeCompatError)?;
    let y1 = F::from_str(y1).map_err(|_| SerdeCompatError)?;
    let z0 = F::from_str(z0).map_err(|_| SerdeCompatError)?;
    let z1 = F::from_str(z1).map_err(|_| SerdeCompatError)?;

    let x = QuadExtField::<Q>::new(x0, x1);
    let y = QuadExtField::<Q>::new(y0, y1);
    let z = QuadExtField::<Q>::new(z0, z1);
    let p = Projective::<G2>::new_unchecked(x, y, z).into_affine();
    if p.is_zero() {
        return Ok(p);
    }
    if CHECK && !p.is_on_curve() {
        return Err(SerdeCompatError);
    }
    if CHECK && !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerdeCompatError);
    }
    Ok(p)
}

struct G1Visitor<const CHECK: bool, F, G1>(PhantomData<G1>)
where
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>;

struct G2Visitor<const CHECK: bool, F, Q, G2>(PhantomData<G2>)
where
    F: PrimeField,
    Q: QuadExtConfig<BaseField = F>,
    G2: SWCurveConfig<BaseField = QuadExtField<Q>>;

struct GtVisitor<F, Fp2, Fp6, Fp12>(PhantomData<Fp12>)
where
    F: PrimeField,
    Fp2: QuadExtConfig<BaseField = F>,
    Fp6: CubicExtConfig<BaseField = QuadExtField<Fp2>>,
    Fp12: QuadExtConfig<BaseField = CubicExtField<Fp6>>;

struct G1SeqVisitor<const CHECK: bool, F, G1>(PhantomData<G1>)
where
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>;

impl<'de, F: PrimeField> de::Visitor<'de> for PrimeFieldVisitor<F> {
    type Value = F;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!(
            "a string representing a field element in F_{}",
            F::MODULUS
        ))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        F::from_str(v).map_err(|_| E::custom("Invalid data"))
    }
}

impl<'de, F: PrimeField> de::Visitor<'de> for PrimeFieldSeqVisitor<F> {
    type Value = Vec<F>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!(
            "a sequence of strings representing field elements in F_{}",
            F::MODULUS
        ))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = vec![];
        while let Some(s) = seq.next_element::<String>()? {
            values.push(F::from_str(&s).map_err(|_| de::Error::custom("invalid field element"))?);
        }
        Ok(values)
    }
}

impl<'de, F, Fp2, Fp6, Fp12> de::Visitor<'de> for GtVisitor<F, Fp2, Fp6, Fp12>
where
    F: PrimeField,
    Fp2: QuadExtConfig<BaseField = F>,
    Fp6: CubicExtConfig<BaseField = QuadExtField<Fp2>>,
    Fp12: QuadExtConfig<BaseField = CubicExtField<Fp6>>,
{
    type Value = QuadExtField<Fp12>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(
                "An element of Fp12 represented as string with radix 10. Must be a sequence of form [[[String; 2]; 3]; 2]."
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
            Ok(QuadExtField::new(c0, c1))
        }
    }
}

/// Constructs a cubic extension field element from a nested vector of strings.
///
/// Expects a vector of three vectors, each containing two strings representing
/// an Fq2 element. Returns an Fq6 element.
#[inline]
fn cubic_extension_field_from_vec<F, Fp2, Fp6>(
    strings: Vec<Vec<String>>,
) -> Result<CubicExtField<Fp6>, SerdeCompatError>
where
    F: PrimeField,
    Fp2: QuadExtConfig<BaseField = F>,
    Fp6: CubicExtConfig<BaseField = QuadExtField<Fp2>>,
{
    if strings.len() != 3 {
        Err(SerdeCompatError)
    } else {
        let c0 = quadratic_extension_field_from_vec(&strings[0])?;
        let c1 = quadratic_extension_field_from_vec(&strings[1])?;
        let c2 = quadratic_extension_field_from_vec(&strings[2])?;
        Ok(CubicExtField::new(c0, c1, c2))
    }
}

/// Constructs a quadratic extension field element from a slice of strings.
///
/// Expects exactly two strings representing the two components of an Fq2 element.
#[inline]
fn quadratic_extension_field_from_vec<F, Fp2>(
    strings: &[String],
) -> Result<QuadExtField<Fp2>, SerdeCompatError>
where
    F: PrimeField,
    Fp2: QuadExtConfig<BaseField = F>,
{
    if strings.len() != 2 {
        Err(SerdeCompatError)
    } else {
        let c0 = F::from_str(&strings[0]).map_err(|_| SerdeCompatError)?;
        let c1 = F::from_str(&strings[1]).map_err(|_| SerdeCompatError)?;
        Ok(QuadExtField::new(c0, c1))
    }
}

impl<'de, const CHECK: bool, F, G1> de::Visitor<'de> for G1SeqVisitor<CHECK, F, G1>
where
    F: PrimeField,
    G1: SWCurveConfig<BaseField = F>,
{
    type Value = Vec<Affine<G1>>;

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
                    g1_from_strings_projective::<CHECK, _, _>(&point[0], &point[1], &point[2])
                        .map_err(|_| {
                            de::Error::custom("Invalid projective point on G1.".to_owned())
                        })?,
                );
            }
        }
        Ok(values)
    }
}

#[cfg(feature = "bn254")]
impl_macro::impl_json_canonical!(ark_bn254, Bn254, bn254);

#[cfg(feature = "bls12-381")]
impl_macro::impl_json_canonical!(ark_bls12_381, Bls12_381, bls12_381);

#[cfg(feature = "babyjubjub")]
pub mod babyjubjub;
