//! This module defines types related to Plonk used in circom and utilities to read these types from files.

#[cfg(feature = "proof")]
mod proof;
#[cfg(feature = "verification-key")]
mod verification_key;
#[cfg(feature = "zkey")]
mod zkey;

#[cfg(feature = "proof")]
pub use proof::PlonkProof;
#[cfg(feature = "verification-key")]
pub use verification_key::VerificationKey;
#[cfg(feature = "zkey")]
pub use zkey::{Additions, CircomPolynomial, VerifyingKey, ZKey};
