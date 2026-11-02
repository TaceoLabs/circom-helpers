#![warn(missing_docs)]
//! Types and utilities for reading Circom-generated files into arkworks representations.
//!
//! This crate provides deserialization support for Circom's binary and JSON formats,
//! including proofs, verification keys, witnesses, R1CS constraint systems, and zkeys
//! for both Groth16 and PLONK proof systems.
#[cfg(all(feature = "zkey", any(feature = "groth16", feature = "plonk")))]
mod binfile;
#[cfg(feature = "groth16")]
pub mod groth16;
#[cfg(feature = "plonk")]
pub mod plonk;

#[cfg(feature = "r1cs")]
mod r1cs;
pub mod traits;

#[cfg(feature = "witness")]
mod witness;

#[cfg(feature = "r1cs")]
pub use r1cs::R1CS;
#[cfg(feature = "r1cs")]
pub use r1cs::R1CSParserError;

#[cfg(feature = "witness")]
pub use witness::Witness;
#[cfg(feature = "witness")]
pub use witness::WitnessParserError;

#[cfg(all(feature = "zkey", any(feature = "groth16", feature = "plonk")))]
pub use binfile::ZkeyParserError;

pub use ark_serde_compat::CheckElement;

// re-export ark_bn254
#[cfg(feature = "bn254")]
pub use ark_bn254;

// re-export ark_bls12_381
#[cfg(feature = "bls12-381")]
pub use ark_bls12_381;

#[cfg(any(feature = "r1cs", feature = "witness"))]
pub(crate) mod reader_utils {
    use ark_ff::PrimeField;
    use ark_serialize::Read;
    use std::{io, str::Utf8Error};
    use thiserror::Error;

    /// Error type describing errors during reading Circom file headers
    #[derive(Debug, Error)]
    pub enum InvalidHeaderError {
        /// Error during IO operations (reading/opening file, etc.)
        #[error(transparent)]
        IoError(#[from] std::io::Error),
        /// File header is not valid UTF-8
        #[error(transparent)]
        Utf8Error(#[from] Utf8Error),
        /// File header does not match the expected header
        #[error("Wrong header. Expected {0} but got {1}")]
        WrongHeader(String, String),
    }

    pub(crate) fn read_header<R: Read>(
        mut reader: R,
        should_header: &str,
    ) -> Result<(), InvalidHeaderError> {
        let mut buf = [0_u8; 4];
        reader.read_exact(&mut buf)?;
        let is_header = std::str::from_utf8(&buf[..])?;
        if is_header == should_header {
            Ok(())
        } else {
            Err(InvalidHeaderError::WrongHeader(
                should_header.to_owned(),
                is_header.to_owned(),
            ))
        }
    }

    pub(crate) fn prime_field_from_reader<F: PrimeField>(
        mut reader: impl Read,
        size: usize,
    ) -> io::Result<F> {
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf[..])?;
        Ok(F::from_le_bytes_mod_order(&buf))
    }

    // pub(crate) fn from_reader_for_groth16_zkey(reader: impl Read) -> SerResult<Self> {
    //     Ok(Self::new_unchecked(
    //         Self::montgomery_bigint_from_reader(reader)?.into_bigint(),
    //     ))
    // }
}

#[cfg(test)]
pub(crate) mod tests {
    // allow the tests folder to be unused in case we turn off the features
    #![allow(unused, reason = "unused when all curve features are disabled")]
    use std::path::PathBuf;

    #[cfg(feature = "bn254")]
    pub(crate) fn groth16_bn254_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/groth16/bn254")
    }

    #[cfg(feature = "bn254")]
    pub(crate) fn plonk_bn254_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/plonk/bn254")
    }

    #[cfg(feature = "bls12-381")]
    pub(crate) fn groth16_bls12_381_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/groth16/bls12_381")
    }

    #[cfg(feature = "bls12-381")]
    pub(crate) fn plonk_bls12_381_kats() -> PathBuf {
        let cargo_manifest = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        cargo_manifest.join("kats/plonk/bls12_381")
    }

    /// Offset of the data of section `id` in a bin file (zkey, r1cs, wtns share the layout).
    pub(crate) fn section_offset(bytes: &[u8], id: u32) -> usize {
        let n_sections = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let mut pos = 12;
        for _ in 0..n_sections {
            let sec_id = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
            let len = u64::from_le_bytes(bytes[pos + 4..pos + 12].try_into().unwrap());
            if sec_id == id {
                return pos + 12;
            }
            pos += 12 + usize::try_from(len).unwrap();
        }
        panic!("section {id} not found");
    }

    pub(crate) fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}

/// Makes oversized allocations fail instead of thrashing the machine, so tests that feed
/// header-driven lengths to the parsers abort immediately if a parser trusts them.
/// Test-only.
#[cfg(test)]
mod alloc_guard {
    use std::alloc::{GlobalAlloc, Layout, System};

    const LIMIT: usize = 1 << 30;

    struct Guard;

    // SAFETY: every method forwards to `System` with the unchanged arguments, and only
    // returns null (allocation failure) for requests above `LIMIT`.
    unsafe impl GlobalAlloc for Guard {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if layout.size() > LIMIT {
                return std::ptr::null_mut();
            }
            // SAFETY: same layout as the caller's, which upholds `GlobalAlloc::alloc`'s contract.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if layout.size() > LIMIT {
                return std::ptr::null_mut();
            }
            // SAFETY: same layout as the caller's.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            if new_size > LIMIT {
                return std::ptr::null_mut();
            }
            // SAFETY: `ptr` and `layout` come from a previous allocation by this allocator.
            unsafe { System.realloc(ptr, layout, new_size) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` and `layout` come from a previous allocation by this allocator.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GUARD: Guard = Guard;
}

#[cfg(test)]
pub(crate) mod test_utils {
    #![allow(unused, reason = "unused when all curve features are disabled")]
    #[cfg(feature = "bls12-381")]
    macro_rules! to_g1_bls12_381 {
        ($x: expr, $y: expr) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bls12_381::Bls12_381 as Pairing>::G1Affine::new(
                ark_bls12_381::Fq::from_str($x).unwrap(),
                ark_bls12_381::Fq::from_str($y).unwrap(),
            )
        }};
    }
    #[cfg(feature = "bls12-381")]
    macro_rules! to_g2_bls12_381 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bls12_381::Bls12_381 as Pairing>::G2Affine::new(
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($x1).unwrap(),
                    ark_bls12_381::Fq::from_str($x2).unwrap(),
                ),
                ark_bls12_381::Fq2::new(
                    ark_bls12_381::Fq::from_str($y1).unwrap(),
                    ark_bls12_381::Fq::from_str($y2).unwrap(),
                ),
            )
        }};
    }

    #[cfg(feature = "bn254")]
    macro_rules! to_g1_bn254 {
        ($x: expr, $y: expr) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bn254::Bn254 as Pairing>::G1Affine::new(
                ark_bn254::Fq::from_str($x).unwrap(),
                ark_bn254::Fq::from_str($y).unwrap(),
            )
        }};
    }

    #[cfg(feature = "bn254")]
    macro_rules! to_g2_bn254 {
        ({$x1: expr, $x2: expr}, {$y1: expr, $y2: expr}) => {{
            use ark_ec::pairing::Pairing;
            use std::str::FromStr;
            <ark_bn254::Bn254 as Pairing>::G2Affine::new(
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($x1).unwrap(),
                    ark_bn254::Fq::from_str($x2).unwrap(),
                ),
                ark_bn254::Fq2::new(
                    ark_bn254::Fq::from_str($y1).unwrap(),
                    ark_bn254::Fq::from_str($y2).unwrap(),
                ),
            )
        }};
    }
    #[cfg(feature = "bls12-381")]
    pub(crate) use to_g1_bls12_381;
    #[cfg(feature = "bn254")]
    pub(crate) use to_g1_bn254;
    #[cfg(feature = "bls12-381")]
    pub(crate) use to_g2_bls12_381;
    #[cfg(feature = "bn254")]
    pub(crate) use to_g2_bn254;
}
