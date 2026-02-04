#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
#![deny(missing_docs)]
use std::str::FromStr;
use std::{fmt, marker::PhantomData};

use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{
    CubicExtConfig, CubicExtField, Field, Fp12Config, Fp12ConfigWrapper, PrimeField, QuadExtConfig,
    QuadExtField, Zero,
};
use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _, Compress};
use num_bigint::Sign;
use serde::ser::Error;
use serde::{
    Serializer,
    de::{self},
    ser::SerializeSeq as _,
};

#[cfg(test)]
mod test;

#[cfg(any(feature = "bn254", feature = "bls12-381"))]
mod impl_macro;

/// Trait providing serialization for pairing-friendly elliptic curves.
///
/// This trait defines a standard interface for serializing and deserializing pairing curve
/// elements (G1, G2, GT) to and from both human-readable and non-human readable formats.
/// It is implemented for specific pairing curves like BN254 and BLS12-381.
///
/// For human-readable formats (JSON), the serialization uses decimal strings for field
/// elements and arrays of strings for group elements to ensure compatibility with Circom
/// and other tools. For non-human readable formats (bincode, CBOR), it uses `ark-serialize`
/// with compressed mode.
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
#[derive(Debug)]
pub(crate) struct SerdeCompatError(&'static str);

impl fmt::Display for SerdeCompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

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

/// Serialize a prime field element.
///
/// For human-readable formats (JSON), serializes as a decimal string.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    if ser.is_human_readable() {
        ser.serialize_str(&p.to_string())
    } else {
        let mut bytes = Vec::with_capacity(p.serialized_size(Compress::Yes));
        p.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Serialize a sequence of prime field elements.
///
/// For human-readable formats (JSON), serializes as an array of decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    if ser.is_human_readable() {
        let mut seq = ser.serialize_seq(Some(ps.len()))?;
        for p in ps {
            seq.serialize_element(&p.to_string())?;
        }
        seq.end()
    } else {
        let mut bytes = Vec::with_capacity(ps.serialized_size(Compress::Yes));
        ps.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Deserialize a prime field element. Allows negative values and is consistent with Circom's negative value parsing. Will return an error if element is larger than modulus.
///
/// This adds malleability as (p-1) and 1 result in the same value due to the implementation of Circom, where a number (-x) is defined as p - x, where p is the modulus of the prime field.
///
/// For human-readable formats (JSON), deserializes from a decimal string.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
///
/// # Example
///
/// ```ignore
/// use serde::Deserialize;
/// use ark_bn254::Fr;
///
/// #[derive(Deserialize)]
/// struct MyStruct {
///     #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f_signed")]
///     field: Fr,
/// }
/// ```
pub fn deserialize_f_signed<'de, F, D>(deserializer: D) -> Result<F, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
{
    let visitor = PrimeFieldVisitor::<false, F>::default();
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize an unsigned prime field element. Returns an error if the value is negative or larger than modulus.
///
/// For human-readable formats (JSON), deserializes from a decimal string.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    let visitor = PrimeFieldVisitor::<true, F>::default();
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a sequence of prime field elements.
///
/// For human-readable formats (JSON), deserializes from an array of decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    let visitor = PrimeFieldSeqVisitor::<true, F> {
        phantom_data: PhantomData,
    };
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a sequence of prime field elements. Allows negative values and is consistent with Circom's negative value parsing. Will return an error if element is larger than modulus.
///
/// This adds malleability as (p-1) and 1 result in the same value due to the implementation of Circom, where a number (-x) is defined as p - x, where p is the modulus of the prime field.
///
///
/// For human-readable formats (JSON), deserializes from an array of decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
///
/// # Example
///
/// ```ignore
/// use serde::Deserialize;
/// use ark_bn254::Fr;
///
/// #[derive(Deserialize)]
/// struct MyStruct {
///     #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f_seq_signed")]
///     fields: Vec<Fr>,
/// }
/// ```
pub fn deserialize_f_seq_signed<'de, D, F>(deserializer: D) -> Result<Vec<F>, D::Error>
where
    D: de::Deserializer<'de>,
    F: PrimeField,
{
    let visitor = PrimeFieldSeqVisitor::<false, F> {
        phantom_data: PhantomData,
    };
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Serialize a G1 affine point.
///
/// For human-readable formats (JSON), serializes as an array of three projective coordinate
/// strings `[x, y, z]`. The point at infinity is represented as `["0", "1", "0"]`.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
///
/// This is a generic function that works with any curve implementing `AffineRepr`.
/// For curve-specific helpers, see the module functions like `bn254::serialize_g1`.
pub fn serialize_g1<S: Serializer, F: Field>(
    p: &impl AffineRepr<BaseField = F>,
    ser: S,
) -> Result<S::Ok, S::Error> {
    if ser.is_human_readable() {
        let strings = g1_to_strings_projective(p);
        let mut seq = ser.serialize_seq(Some(strings.len()))?;
        for ele in strings {
            seq.serialize_element(&ele)?;
        }
        seq.end()
    } else {
        let mut bytes = Vec::with_capacity(p.serialized_size(Compress::Yes));
        p.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Serialize a G2 affine point.
///
/// For human-readable formats (JSON), serializes as a 3×2 array of projective coordinate
/// strings `[[x0, x1], [y0, y1], [z0, z1]]`, where each coordinate is represented as a
/// quadratic extension field element (two components). The point at infinity is represented
/// as `[["0", "0"], ["1", "0"], ["0", "0"]]`.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    if ser.is_human_readable() {
        let mut x_seq = ser.serialize_seq(Some(3))?;
        let (x, y) = p
            .xy()
            .unwrap_or((QuadExtField::<F>::zero(), QuadExtField::<F>::zero()));
        x_seq.serialize_element(&[x.c0.to_string(), x.c1.to_string()])?;
        x_seq.serialize_element(&[y.c0.to_string(), y.c1.to_string()])?;
        x_seq.serialize_element(&["1", "0"])?;
        x_seq.end()
    } else {
        let mut bytes = Vec::with_capacity(p.serialized_size(Compress::Yes));
        p.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Serialize a target group (GT/Fq12) element.
///
/// For human-readable formats (JSON), serializes as a 2×3×2 array of decimal strings.
/// An Fq12 element is viewed as two Fq6 components, each containing three Fq2 components,
/// where each Fq2 is a pair of base field elements. The resulting structure is
/// `[[[a00, a01], [a10, a11], [a20, a21]], [[b00, b01], [b10, b11], [b20, b21]]]`,
/// where each innermost pair represents an Fq2 element as decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    if ser.is_human_readable() {
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
    } else {
        let mut bytes = Vec::with_capacity(p.serialized_size(Compress::Yes));
        p.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
}

/// Serialize a sequence of G1 affine points.
///
/// For human-readable formats (JSON), serializes as an array of projective coordinate arrays
/// where each point is represented as `[x, y, z]` with decimal strings. The point at infinity
/// is represented as `["0", "1", "0"]`.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
///
/// This is a generic function. For curve-specific helpers, see the module functions
/// like `bn254::serialize_g1_seq`.
pub fn serialize_g1_seq<S: Serializer, F: PrimeField>(
    ps: &[impl AffineRepr<BaseField = F>],
    ser: S,
) -> Result<S::Ok, S::Error> {
    if ser.is_human_readable() {
        let mut seq = ser.serialize_seq(Some(ps.len()))?;
        for p in ps {
            seq.serialize_element(&g1_to_strings_projective(p))?;
        }
        seq.end()
    } else {
        let mut bytes = Vec::with_capacity(ps.serialized_size(Compress::Yes));
        ps.serialize_compressed(&mut bytes)
            .map_err(|_| S::Error::custom("cannot canonical serialize element"))?;
        ser.serialize_bytes(&bytes)
    }
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
pub(crate) struct PrimeFieldVisitor<const UNSIGNED: bool, F> {
    phantom_data: PhantomData<F>,
}

#[derive(Default)]
pub(crate) struct PrimeFieldSeqVisitor<const UNSIGNED: bool, F> {
    phantom_data: PhantomData<F>,
}

/// Deserialize a G1 affine point with full validation.
///
/// For human-readable formats (JSON), deserializes from `[x, y, z]` format as decimal strings.
/// The point at infinity must be `["0", "1", "0"]`.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
/// Performs full validation including field element decoding, on-curve check, and
/// subgroup membership verification.
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
    let visitor = G1Visitor::<true, _, _>(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a G1 affine point without validation.
///
/// For human-readable formats (JSON), deserializes from `[x, y, z]` format as decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    let visitor = G1Visitor::<false, _, _>(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a G2 affine point with full validation.
///
/// For human-readable formats (JSON), deserializes from `[[x0, x1], [y0, y1], [z0, z1]]`
/// format as decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
/// Performs full validation including field element decoding, on-curve check, and
/// subgroup membership verification.
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
    let visitor = G2Visitor::<true, _, _, _>(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a G2 affine point without validation.
///
/// For human-readable formats (JSON), deserializes from `[[x0, x1], [y0, y1], [z0, z1]]`
/// format as decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
/// **Does not** perform validation checks (field canonical form, on-curve, subgroup membership),
/// making it significantly faster but potentially unsafe.
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
    let visitor = G2Visitor::<false, _, _, _>(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}
/// Deserialize a target group (GT/Fq12) element.
///
/// For human-readable formats (JSON), deserializes from the nested array structure
/// `[[[a00, a01], [a10, a11], [a20, a21]], [[b00, b01], [b10, b11], [b20, b21]]]`.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
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
    let visitor = GtVisitor(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a sequence of G1 affine points with full validation.
///
/// For human-readable formats (JSON), deserializes from an array of G1 points where each
/// point is in `[x, y, z]` projective format as decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
/// Performs full validation for each point including field element decoding, on-curve check,
/// and subgroup membership verification.
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
    let visitor = G1SeqVisitor::<true, _, _>(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// Deserialize a sequence of G1 affine points without validation.
///
/// For human-readable formats (JSON), deserializes from an array of G1 points where each
/// point is in `[x, y, z]` projective format as decimal strings.
/// For non-human readable formats (bincode, CBOR), uses `ark-serialize` with compressed mode.
/// **Does not** perform validation checks for any point, making it significantly faster but
/// potentially unsafe.
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
    let visitor = G1SeqVisitor::<false, _, _>(PhantomData);
    if deserializer.is_human_readable() {
        deserializer.deserialize_seq(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
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
            g1_from_strings_projective::<CHECK, _, _>(&x, &y, &z).map_err(de::Error::custom)
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
                .map_err(de::Error::custom)
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
    let x = parse_field_str_inner_unsigned(x)?;
    let y = parse_field_str_inner_unsigned(y)?;
    let z = parse_field_str_inner_unsigned(z)?;
    let p = Projective::<G1>::new_unchecked(x, y, z).into_affine();
    if p.is_zero() {
        return Ok(p);
    }
    if CHECK && !p.is_on_curve() {
        return Err(SerdeCompatError("not con curve"));
    }
    if CHECK && !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerdeCompatError("not in correct subgroup"));
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
    let x0 = parse_field_str_inner_unsigned(x0)?;
    let x1 = parse_field_str_inner_unsigned(x1)?;
    let y0 = parse_field_str_inner_unsigned(y0)?;
    let y1 = parse_field_str_inner_unsigned(y1)?;
    let z0 = parse_field_str_inner_unsigned(z0)?;
    let z1 = parse_field_str_inner_unsigned(z1)?;

    let x = QuadExtField::<Q>::new(x0, x1);
    let y = QuadExtField::<Q>::new(y0, y1);
    let z = QuadExtField::<Q>::new(z0, z1);
    let p = Projective::<G2>::new_unchecked(x, y, z).into_affine();
    if p.is_zero() {
        return Ok(p);
    }
    if CHECK && !p.is_on_curve() {
        return Err(SerdeCompatError("not on curve"));
    }
    if CHECK && !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerdeCompatError("not on correct subgroup"));
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

impl<'de, const UNSIGNED: bool, F: PrimeField> de::Visitor<'de> for PrimeFieldVisitor<UNSIGNED, F> {
    type Value = F;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!(
            "a string representing a field element in F_{}",
            F::MODULUS
        ))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::deserialize_compressed(v).map_err(|err| de::Error::custom(err.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_field_str_inner::<UNSIGNED, F>(v).map_err(E::custom)
    }
}

impl<'de, const UNSIGNED: bool, F: PrimeField> de::Visitor<'de>
    for PrimeFieldSeqVisitor<UNSIGNED, F>
{
    type Value = Vec<F>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!(
            "a sequence of strings representing field elements in F_{}",
            F::MODULUS
        ))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::deserialize_compressed(v).map_err(|err| de::Error::custom(err.to_string()))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        use serde::de::Error;
        let mut values = if let Some(size_hint) = seq.size_hint() {
            Vec::with_capacity(size_hint)
        } else {
            Vec::new()
        };
        while let Some(s) = seq.next_element::<String>()? {
            values.push(parse_field_str_inner::<UNSIGNED, F>(&s).map_err(A::Error::custom)?);
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

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::Value::deserialize_compressed(v).map_err(de::Error::custom)
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
            let c0 = cubic_extension_field_from_vec(x).map_err(de::Error::custom)?;
            let c1 = cubic_extension_field_from_vec(y).map_err(de::Error::custom)?;
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
        Err(SerdeCompatError("expected cubic extension field"))
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
        Err(SerdeCompatError("expected quadratic extension field"))
    } else {
        let c0 = parse_field_str_inner_unsigned(&strings[0])?;
        let c1 = parse_field_str_inner_unsigned(&strings[1])?;
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

#[inline]
fn parse_field_str_inner<const UNSIGNED: bool, F: PrimeField>(
    v: &str,
) -> Result<F, SerdeCompatError> {
    // forbid starting + sign
    if v.starts_with('+') {
        return Err(SerdeCompatError("invalid leading + sign for number"));
    }
    if UNSIGNED && v.starts_with('-') {
        return Err(SerdeCompatError("only expects positive numbers"));
    }
    if UNSIGNED {
        if v.chars().any(|x| !x.is_ascii_digit()) {
            return Err(SerdeCompatError("only expects digits 0-9 for numbers"));
        }
    } else if v
        .strip_prefix('-')
        .unwrap_or(v)
        .chars()
        .any(|x| !x.is_ascii_digit())
    {
        return Err(SerdeCompatError("only expects digits 0-9 for numbers"));
    }
    // need to do this double hop because BigInteger trait only has try_from for BigUint. Also we now do this conversion for every time we call this function, which is not super nice, but this also happens when using from_str as well
    let modulus =
        num_bigint::BigInt::from(num_bigint::BigUint::try_from(F::MODULUS).map_err(|_| {
            SerdeCompatError(
                "Cannot modulus of this prime field to BigUint - prime field not supported",
            )
        })?);
    let mut number =
        num_bigint::BigInt::from_str(v).map_err(|_| SerdeCompatError("invalid data"))?;
    if number.is_zero() && v != "0" {
        return Err(SerdeCompatError("zero must be serialized as '0'"));
    }
    if v.starts_with("0") && !number.is_zero() {
        return Err(SerdeCompatError("invalid leading zeros for number"));
    }
    if !UNSIGNED && number.sign() == Sign::Minus {
        if !number.is_zero() && v.starts_with("-0") {
            return Err(SerdeCompatError(
                "invalid leading zeros for negative number",
            ));
        }
        // We are in the sign case and the value is negative - to be compatible with Circom we add the modulus.
        number += modulus;
        // If the number is still negative, the value is larger than the Modulus. We reject this here. This allows us to call BigUint::try_from afterwards, as we know for sure the value is positive.
        if number.sign() == Sign::Minus {
            return Err(SerdeCompatError("doesn't fit into field"));
        }
    } else if UNSIGNED && number.sign() == Sign::Minus {
        return Err(SerdeCompatError("only expects positive numbers"));
    } else if modulus <= number {
        return Err(SerdeCompatError("doesn't fit into field"));
    }
    let number = num_bigint::BigUint::try_from(number).expect("Works due to checks above");
    // this should never happen for the fields we implement
    let number = F::BigInt::try_from(number)
        .map_err(|_| SerdeCompatError("Cannot convert to underlying BigInt again"))?;
    Ok(F::from_bigint(number).expect("Is some due to checks above"))
}

#[inline(always)]
fn parse_field_str_inner_unsigned<F: PrimeField>(v: &str) -> Result<F, SerdeCompatError> {
    parse_field_str_inner::<true, F>(v)
}

#[cfg(feature = "bn254")]
impl_macro::impl_json_canonical!(ark_bn254, Bn254, bn254);

#[cfg(feature = "bls12-381")]
impl_macro::impl_json_canonical!(ark_bls12_381, Bls12_381, bls12_381);

#[cfg(feature = "babyjubjub")]
pub mod babyjubjub;
