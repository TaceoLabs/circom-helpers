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
//! - `bn254`: Enables serialization support for BN254 curve types (enabled by default)
//! - `babyjubjub`: Enables serialization support for BabyJubJub curve types (enabled by default)
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
//!     #[serde(serialize_with = "taceo_ark_serde_compat::bn254::serialize_fr")]
//!     #[serde(deserialize_with = "taceo_ark_serde_compat::bn254::deserialize_fr")]
//!     field: Fr,
//! }
//! ```

#![deny(missing_docs)]
use std::marker::PhantomData;

use ark_ff::PrimeField;
use serde::{Serializer, de};

#[cfg(feature = "babyjubjub")]
/// BabyJubJub curve serialization and deserialization functions.
///
/// This module provides serde-compatible functions for serializing and deserializing
/// BabyJubJub curve types (field elements and curve points) as strings.
pub mod babyjubjub;
#[cfg(feature = "bn254")]
/// BN254 curve serialization and deserialization functions.
///
/// This module provides serde-compatible functions for serializing and deserializing
/// BN254 curve types (field elements, G1, G2, and GT points) as strings and arrays.
pub mod bn254;

#[cfg(any(feature = "bn254", feature = "babyjubjub"))]
pub(crate) struct SerdeCompatError;

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

#[derive(Default)]
pub(crate) struct PrimeFieldVisitor<F> {
    phantom_data: PhantomData<F>,
}

impl<'de, F: PrimeField> de::Visitor<'de> for PrimeFieldVisitor<F> {
    type Value = F;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sting representing a bn254 Fr element")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        F::from_str(v).map_err(|_| E::custom("Invalid data"))
    }
}
