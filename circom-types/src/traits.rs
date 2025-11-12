//! Traits for converting circom file formats to arkworks types.

use std::io::Read;

use ark_ec::pairing::Pairing;
use ark_serialize::SerializationError;
use taceo_ark_serde_compat::{CanonicalJsonSerialize, CheckElement};
#[allow(unused)]
type SerResult<T> = Result<T, SerializationError>;

#[cfg(any(feature = "bn254", feature = "bls12-381"))]
macro_rules! impl_serde_for_curve {
    ($mod_name: ident, $config: ident, $curve: ident, $name: expr, $field_size: expr, $scalar_field_size: expr, $circom_name: expr) => {
        mod $mod_name {

            use std::io::Read;

            use ark_ec::AffineRepr;
            use ark_ff::{PrimeField, Zero};
            use taceo_ark_serde_compat::CheckElement;

            use ark_serialize::{CanonicalDeserialize, SerializationError};
            use $curve::{Fq2, $config};

            use super::*;

            impl CircomArkworksPairingBridge for $config {
                const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = $field_size;
                const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = $field_size * 2;
                const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = $field_size * 2;
                const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = $field_size * 2 * 2;
                const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize = 0;
                const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize = 0;

                const SCALAR_FIELD_BYTE_SIZE: usize = $scalar_field_size;
                const BASE_FIELD_BYTE_SIZE: usize = $field_size;

                fn get_circom_name() -> String {
                    $circom_name.to_owned()
                }

                //Circom serializes its field elements in montgomery form
                //therefore we use Self::fq_from_montgomery_reader
                fn g1_from_bytes(bytes: &[u8], check: CheckElement) -> SerResult<Self::G1Affine> {
                    //already in montgomery form
                    let x = Self::fq_from_montgomery_reader(&bytes[..Self::BASE_FIELD_BYTE_SIZE])?;
                    let y = Self::fq_from_montgomery_reader(&bytes[Self::BASE_FIELD_BYTE_SIZE..])?;

                    if x.is_zero() && y.is_zero() {
                        return Ok(Self::G1Affine::zero());
                    }

                    let p = Self::G1Affine::new_unchecked(x, y);

                    let curve_checks = matches!(check, CheckElement::Yes);
                    if curve_checks && !p.is_on_curve() {
                        return Err(SerializationError::InvalidData);
                    }
                    if curve_checks && !p.is_in_correct_subgroup_assuming_on_curve() {
                        return Err(SerializationError::InvalidData);
                    }
                    Ok(p)
                }

                fn g2_from_bytes(bytes: &[u8], check: CheckElement) -> SerResult<Self::G2Affine> {
                    //already in montgomery form
                    let x0 = Self::fq_from_montgomery_reader(&bytes[..Self::BASE_FIELD_BYTE_SIZE])?;
                    let x1 = Self::fq_from_montgomery_reader(
                        &bytes[Self::BASE_FIELD_BYTE_SIZE..Self::BASE_FIELD_BYTE_SIZE * 2],
                    )?;
                    let y0 = Self::fq_from_montgomery_reader(
                        &bytes[Self::BASE_FIELD_BYTE_SIZE * 2..Self::BASE_FIELD_BYTE_SIZE * 3],
                    )?;
                    let y1 = Self::fq_from_montgomery_reader(
                        &bytes[Self::BASE_FIELD_BYTE_SIZE * 3..Self::BASE_FIELD_BYTE_SIZE * 4],
                    )?;

                    let x = Fq2::new(x0, x1);
                    let y = Fq2::new(y0, y1);

                    if x.is_zero() && y.is_zero() {
                        return Ok(Self::G2Affine::zero());
                    }

                    let p = Self::G2Affine::new_unchecked(x, y);

                    let curve_checks = matches!(check, CheckElement::Yes);
                    if curve_checks && !p.is_on_curve() {
                        return Err(SerializationError::InvalidData);
                    }
                    if curve_checks && !p.is_in_correct_subgroup_assuming_on_curve() {
                        return Err(SerializationError::InvalidData);
                    }
                    Ok(p)
                }

                fn g1_from_reader(
                    mut reader: impl Read,
                    check: CheckElement,
                ) -> SerResult<Self::G1Affine> {
                    let mut buf = [0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
                    reader.read_exact(&mut buf)?;
                    Self::g1_from_bytes(&buf, check)
                }

                fn g2_from_reader(
                    mut reader: impl Read,
                    check: CheckElement,
                ) -> SerResult<Self::G2Affine> {
                    let mut buf = [0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED];
                    reader.read_exact(&mut buf)?;
                    Self::g2_from_bytes(&buf, check)
                }

                fn fr_from_montgomery_reader(
                    mut reader: impl Read,
                ) -> SerResult<Self::ScalarField> {
                    let mut buf = [0u8; Self::SCALAR_FIELD_BYTE_SIZE];
                    reader.read_exact(&mut buf)?;
                    let bigint =
                        <Self::ScalarField as PrimeField>::BigInt::deserialize_uncompressed(
                            buf.as_slice(),
                        )?;
                    Ok(Self::ScalarField::new_unchecked(bigint))
                }

                fn fq_from_montgomery_reader(mut reader: impl Read) -> SerResult<Self::BaseField> {
                    let mut buf = [0u8; Self::BASE_FIELD_BYTE_SIZE];
                    reader.read_exact(&mut buf)?;
                    let bigint = <Self::BaseField as PrimeField>::BigInt::deserialize_uncompressed(
                        buf.as_slice(),
                    )?;
                    Ok(Self::BaseField::new_unchecked(bigint))
                }

                fn fr_from_reader_for_groth16_zkey(
                    reader: impl Read,
                ) -> SerResult<Self::ScalarField> {
                    Ok(Self::ScalarField::new_unchecked(
                        Self::fr_from_montgomery_reader(reader)?.into_bigint(),
                    ))
                }
            }
        }
    };
}

/// Bridge trait to serialize and deserialize pairings contained in circom files into and from [`ark_ec::pairing::Pairing`] representation
pub trait CircomArkworksPairingBridge: Pairing + CanonicalJsonSerialize {
    /// Size of compressed element of G1 in bytes
    const G1_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    /// Size of uncompressed element of G1 in bytes
    const G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    /// Size of compressed element of G2 in bytes
    const G2_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    /// Size of uncompressed element of G2 in bytes
    const G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;
    /// Size of compressed element of Gt in bytes
    const GT_SERIALIZED_BYTE_SIZE_COMPRESSED: usize;
    /// Size of uncompressed element of Gt in bytes
    const GT_SERIALIZED_BYTE_SIZE_UNCOMPRESSED: usize;

    /// Size of element in ScalarField
    const SCALAR_FIELD_BYTE_SIZE: usize;
    /// Size of element in BaseField
    const BASE_FIELD_BYTE_SIZE: usize;
    /// Returns the name of the curve as defined in circom
    fn get_circom_name() -> String;
    /// Deserializes element of G1 from bytes where the element is already in montgomery form (no montgomery reduction performed)
    /// Used in default multithreaded impl of g1_vec_from_reader, because `Read` cannot be shared across threads
    fn g1_from_bytes(bytes: &[u8], check: CheckElement) -> SerResult<Self::G1Affine>;
    /// Deserializes element of G2 from bytes where the element is already in montgomery form (no montgomery reduction performed)
    /// Used in default multithreaded impl of g2_vec_from_reader, because `Read` cannot be shared across threads
    fn g2_from_bytes(bytes: &[u8], check: CheckElement) -> SerResult<Self::G2Affine>;
    /// Deserializes element of G1 from reader where the element is already in montgomery form (no montgomery reduction performed)
    fn g1_from_reader(reader: impl Read, check: CheckElement) -> SerResult<Self::G1Affine>;
    /// Deserializes element of G2 from reader where the element is already in montgomery form (no montgomery reduction performed)
    fn g2_from_reader(reader: impl Read, check: CheckElement) -> SerResult<Self::G2Affine>;
    /// Deserializes vec of G1 from reader where the elements are already in montgomery form (no montgomery reduction performed)
    fn g1_vec_from_reader(
        mut reader: impl Read,
        num: usize,
        check: CheckElement,
    ) -> SerResult<Vec<Self::G1Affine>> {
        let mut buf = vec![0u8; Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED * num];
        reader.read_exact(&mut buf)?;
        #[cfg(feature = "parallel")]
        use rayon::prelude::*;

        #[cfg(feature = "parallel")]
        let ret_val = buf
            .par_chunks_exact(Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED)
            .map(|chunk| Self::g1_from_bytes(chunk, check))
            .collect::<Result<Vec<_>, SerializationError>>();

        #[cfg(not(feature = "parallel"))]
        let ret_val = buf
            .chunks_exact(Self::G1_SERIALIZED_BYTE_SIZE_UNCOMPRESSED)
            .map(|chunk| Self::g1_from_bytes(chunk, check))
            .collect::<Result<Vec<_>, SerializationError>>();
        ret_val
    }
    /// Deserializes vec of G2 from reader where the elements are already in montgomery form (no montgomery reduction performed)
    /// The default implementation runs multithreaded using rayon
    fn g2_vec_from_reader(
        mut reader: impl Read,
        num: usize,
        check: CheckElement,
    ) -> SerResult<Vec<Self::G2Affine>> {
        let mut buf = vec![0u8; Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED * num];
        reader.read_exact(&mut buf)?;

        #[cfg(feature = "parallel")]
        use rayon::prelude::*;

        #[cfg(feature = "parallel")]
        let ret_val = buf
            .par_chunks_exact(Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED)
            .map(|chunk| Self::g2_from_bytes(chunk, check))
            .collect::<Result<Vec<_>, SerializationError>>();

        #[cfg(not(feature = "parallel"))]
        let ret_val = buf
            .chunks_exact(Self::G2_SERIALIZED_BYTE_SIZE_UNCOMPRESSED)
            .map(|chunk| Self::g2_from_bytes(chunk, check))
            .collect::<Result<Vec<_>, SerializationError>>();
        ret_val
    }

    /// Deserializes an element of [`Pairing::ScalarField`] where the element is already in montgomery form (no montgomery reduction performed).
    fn fr_from_montgomery_reader(reader: impl Read) -> SerResult<Self::ScalarField>;

    /// Deserializes an element of [`Pairing::ScalarField`] where the element is already in montgomery form BUT we still need to perform a montgomery reduction. This is necessary for the deserialization of circom's ZKey.
    fn fr_from_reader_for_groth16_zkey(reader: impl Read) -> SerResult<Self::ScalarField>;

    /// Deserializes an element of [`Pairing::BaseField`] where the element is already in montgomery form (no montgomery reduction performed).
    fn fq_from_montgomery_reader(reader: impl Read) -> SerResult<Self::BaseField>;
}

#[cfg(feature = "bn254")]
impl_serde_for_curve!(bn254, Bn254, ark_bn254, "bn254", 32, 32, "bn128");

#[cfg(feature = "bls12-381")]
impl_serde_for_curve!(
    bls12_381,
    Bls12_381,
    ark_bls12_381,
    "bls12_381",
    48,
    32,
    "bls12381"
);
