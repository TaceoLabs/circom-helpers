//! This module defines the [`PublicInput`] struct that allows loading public inputs from JSON files via [`serde::Deserialize`] and [`serde::Serialize`].

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

/// Represents a public input for a Groth16 proof. Implements [`serde::Deserialize`] and [`serde::Serialize`] for loading/storing public inputs from/to JSON formats defined by Circom.
///
/// # Danger
/// In contrast to most deserialization functions in this crate, this struct explicitly supports signed integers as they are also supported by Circom for public inputs.
/// This means there is inherent malleability in the representation of public inputs, as negative integers can be represented in multiple ways (e.g., -1 and field_modulus - 1).
/// Users of this struct should be aware of this malleability and handle it appropriately in their applications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicInput<F: PrimeField>(
    /// The values of the public input.
    #[serde(serialize_with = "ark_serde_compat::serialize_f_seq")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_f_seq_signed")]
    pub Vec<F>,
);

impl<F: PrimeField> PublicInput<F> {
    /// Consumes `self` and returns the inner values.
    pub fn into_inner(self) -> Vec<F> {
        self.0
    }
}

impl<F: PrimeField> AsRef<[F]> for PublicInput<F> {
    fn as_ref(&self) -> &[F] {
        &self.0
    }
}

#[cfg(test)]
#[cfg(feature = "bls12-381")]
mod bls12_381_tests {

    use super::PublicInput;
    use std::str::FromStr;

    #[test]
    fn can_serde_public_input_bls12_381() {
        let is_public_input_str = "[\"1\",\"2\",\"3\"]";
        let public_input =
            serde_json::from_str::<PublicInput<ark_bls12_381::Fr>>(is_public_input_str).unwrap();
        let should_values = vec![
            ark_bls12_381::Fr::from_str("1").unwrap(),
            ark_bls12_381::Fr::from_str("2").unwrap(),
            ark_bls12_381::Fr::from_str("3").unwrap(),
        ];
        assert_eq!(public_input.0, should_values);
        let ser_public_input = serde_json::to_string(&public_input).unwrap();
        assert_eq!(ser_public_input, is_public_input_str);
        let der_public_input =
            serde_json::from_str::<PublicInput<ark_bls12_381::Fr>>(&ser_public_input).unwrap();
        assert_eq!(der_public_input, public_input);
    }
}

#[cfg(test)]
#[cfg(feature = "bn254")]
mod bn254_tests {

    use super::PublicInput;
    use std::str::FromStr;

    #[test]
    fn can_serde_public_input_bn254() {
        let is_public_input_str = "[\"1\",\"2\",\"3\"]";
        let public_input =
            serde_json::from_str::<PublicInput<ark_bn254::Fr>>(is_public_input_str).unwrap();
        let should_values = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("2").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
        ];
        assert_eq!(public_input.0, should_values);
        let ser_proof = serde_json::to_string(&public_input).unwrap();
        assert_eq!(ser_proof, is_public_input_str);
        let der_proof = serde_json::from_str::<PublicInput<ark_bn254::Fr>>(&ser_proof).unwrap();
        assert_eq!(der_proof, public_input);
    }

    #[test]
    fn can_serde_public_input_bn254_signed() {
        let is_public_input_str = "[\"-1\",\"2\",\"-3\"]";
        let serialized_public_input_str = "[\"21888242871839275222246405745257275088548364400416034343698204186575808495616\",\"2\",\"21888242871839275222246405745257275088548364400416034343698204186575808495614\"]";
        let public_input =
            serde_json::from_str::<PublicInput<ark_bn254::Fr>>(is_public_input_str).unwrap();
        let should_values = vec![
            ark_bn254::Fr::from_str("-1").unwrap(),
            ark_bn254::Fr::from_str("2").unwrap(),
            ark_bn254::Fr::from_str("-3").unwrap(),
        ];
        assert_eq!(public_input.0, should_values);
        let ser_proof = serde_json::to_string(&public_input).unwrap();
        assert_eq!(ser_proof, serialized_public_input_str);
        let der_proof = serde_json::from_str::<PublicInput<ark_bn254::Fr>>(&ser_proof).unwrap();
        assert_eq!(der_proof, public_input);
    }
}
