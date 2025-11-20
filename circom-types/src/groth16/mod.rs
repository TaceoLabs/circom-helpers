//! This module defines types related to Groth16 used in Circom and utilities to read these types from files.
#[cfg(feature = "proof")]
mod proof;
#[cfg(feature = "public-input")]
mod public_input;
#[cfg(feature = "verification-key")]
mod verification_key;
#[cfg(feature = "zkey")]
mod zkey;
#[cfg(feature = "zkey")]
mod zkey_to_ark;

#[cfg(feature = "proof")]
pub use proof::Proof;
#[cfg(feature = "public-input")]
pub use public_input::PublicInput;
#[cfg(feature = "verification-key")]
pub use verification_key::VerificationKey;
#[cfg(feature = "zkey")]
pub use zkey::Zkey;
#[cfg(feature = "zkey")]
pub use zkey_to_ark::{ArkZkey, ConstraintMatricesWrapper};
