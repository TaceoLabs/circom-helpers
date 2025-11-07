#![deny(missing_docs)]
use std::marker::PhantomData;

use ark_ff::PrimeField;
use serde::{Serializer, de};

#[cfg(feature = "babyjubjub")]
pub mod babyjubjub;
#[cfg(feature = "bn254")]
pub mod bn254;

#[cfg(any(feature = "bn254", feature = "babyjubjub"))]
pub(crate) struct SerdeCompatError;

pub fn serialize_f<S: Serializer>(p: &impl PrimeField, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&p.to_string())
}

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
