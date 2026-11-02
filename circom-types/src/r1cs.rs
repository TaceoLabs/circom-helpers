//Copyright (c) 2021 Georgios Konstantopoulos
//
//Permission is hereby granted, free of charge, to any
//person obtaining a copy of this software and associated
//documentation files (the "Software"), to deal in the
//Software without restriction, including without
//limitation the rights to use, copy, modify, merge,
//publish, distribute, sublicense, and/or sell copies of
//the Software, and to permit persons to whom the Software
//is furnished to do so, subject to the following
//conditions:
//
//The above copyright notice and this permission notice
//shall be included in all copies or substantial portions
//of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//IN CONNECTION WITH THE SOFTWARE O THE USE OR OTHER
//DEALINGS IN THE SOFTWARE.R

//! This module provides the [`R1CS`] type which implements [`R1CS::from_reader`] for parsing the R1CS file format used by Circom.
//! Inspired by <https://github.com/arkworks-rs/circom-compat/blob/170b10fc9ed182b5f72ecf379033dda023d0bf07/src/circom/r1cs_reader.rs>
use ark_ff::PrimeField;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Error, ErrorKind};
use thiserror::Error;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::io::{Read, Seek, SeekFrom};

use std::collections::HashMap;

use crate::{
    reader_utils::{self, InvalidHeaderError},
    traits::CircomArkworksPairingBridge,
};

const R1CS_HEADER: &str = "r1cs";
const MAX_VERSION: u32 = 1;
type Result<T> = std::result::Result<T, R1CSParserError>;

//TODO maybe write something better that is not so convoluted to access
pub(crate) type Constraints<P> = (ConstraintVec<P>, ConstraintVec<P>, ConstraintVec<P>);
pub(crate) type ConstraintVec<P> = Vec<(usize, <P as Pairing>::ScalarField)>;

/// Error type describing errors during parsing R1CS files
#[derive(Debug, Error)]
pub enum R1CSParserError {
    /// Error during serialization
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    /// Error during IO operations (reading/opening file, etc.)
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// Error describing that the version of the file is not supported for parsing
    #[error("Max supported version is {0}, but got {1}")]
    VersionNotSupported(u32, u32),
    /// Error during reading circom file header
    #[error(transparent)]
    WrongHeader(#[from] InvalidHeaderError),
    /// Error describing that the `ScalarField` from curve does not match in witness file
    #[error("ScalarField from curve does not match in witness file")]
    WrongScalarField,
}

/// Struct representing a R1CS file produced by Circom that implements [`R1CS::from_reader`] for parsing the R1CS file format used by Circom.
#[derive(Clone, Debug)]
pub struct R1CS<P: Pairing> {
    /// Number of public inputs
    pub num_inputs: usize,
    /// Number of auxiliary variables
    pub num_aux: usize,
    /// Number of variables
    pub num_variables: usize,
    /// Constraints
    pub constraints: Vec<Constraints<P>>,
    /// Mapping from wire to label
    pub wire_mapping: Vec<usize>,
    /// Number of public outputs
    pub n_pub_out: u32,
    /// Number of public inputs
    pub n_pub_in: u32,
    /// Number of private inputs
    pub n_prv_in: u32,
    /// Number of labels
    pub n_labels: u64,
    /// Number of constraints
    pub n_constraints: usize,
}

fn find_section(
    sections: &HashMap<u32, u64>,
    section_type: u32,
    kind: &str,
    name: &str,
) -> std::io::Result<u64> {
    sections.get(&section_type).copied().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            format!("No section {kind} for {name} type found"),
        )
    })
}

impl<P: Pairing + CircomArkworksPairingBridge> R1CS<P> {
    /// Parses an [`R1CS`] file from a reader and returns [`R1CSParserError`] on failure
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be read, is truncated, or fails validation.
    ///
    /// # Panics
    ///
    /// Panics if a `u32` does not fit into `usize`, which can only happen on targets narrower than 32 bits.
    pub fn from_reader<R: Read + Seek>(mut reader: R) -> Result<Self> {
        reader_utils::read_header(&mut reader, R1CS_HEADER)?;
        let version = reader.read_u32::<LittleEndian>()?;
        if version != MAX_VERSION {
            return Err(R1CSParserError::VersionNotSupported(MAX_VERSION, version));
        }
        let num_sections = reader.read_u32::<LittleEndian>()?;

        // todo: handle sec_size correctly
        // section type -> file offset
        let mut sec_offsets = HashMap::<u32, u64>::new();
        let mut sec_sizes = HashMap::<u32, u64>::new();

        // get file offset of each section
        for _ in 0..num_sections {
            let sec_type = reader.read_u32::<LittleEndian>()?;
            let sec_size = reader.read_u64::<LittleEndian>()?;
            let offset = reader.stream_position()?;
            sec_offsets.insert(sec_type, offset);
            sec_sizes.insert(sec_type, sec_size);
            let skip = i64::try_from(sec_size)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "section size too large"))?;
            reader.seek(SeekFrom::Current(skip))?;
        }
        if reader.read(&mut [0u8])? != 0 {
            Err(Error::new(
                ErrorKind::InvalidData,
                "trailing bytes after last section",
            ))?;
        }

        let header_type = 1;
        let constraint_type = 2;
        let wire2label_type = 3;

        let header_offset = find_section(&sec_offsets, header_type, "offset", "header")?;

        reader.seek(SeekFrom::Start(header_offset))?;

        let header_size = find_section(&sec_sizes, header_type, "size", "header")?;

        let field_size =
            usize::try_from(reader.read_u32::<LittleEndian>()?).expect("u32 fits into usize");
        if field_size != P::SCALAR_FIELD_BYTE_SIZE {
            return Err(R1CSParserError::WrongScalarField);
        }

        if header_size != 32 + field_size as u64 {
            return Err(R1CSParserError::WrongScalarField);
        }

        let q = <P::ScalarField as PrimeField>::BigInt::deserialize_uncompressed(&mut reader)?;
        let modulus = P::ScalarField::MODULUS;
        if q != modulus {
            return Err(R1CSParserError::WrongScalarField);
        }

        let num_variables =
            usize::try_from(reader.read_u32::<LittleEndian>()?).expect("u32 fits into usize");
        let n_pub_out = reader.read_u32::<LittleEndian>()?;
        let n_pub_in = reader.read_u32::<LittleEndian>()?;
        let n_prv_in = reader.read_u32::<LittleEndian>()?;
        let n_labels = reader.read_u64::<LittleEndian>()?;
        let n_constraints =
            usize::try_from(reader.read_u32::<LittleEndian>()?).expect("u32 fits into usize");

        let constraint_offset =
            find_section(&sec_offsets, constraint_type, "offset", "constraint")?;

        reader.seek(SeekFrom::Start(constraint_offset))?;

        let constraints =
            read_constraints::<&mut R, P>(&mut reader, n_constraints, num_variables, field_size)?;

        let wire2label_offset =
            find_section(&sec_offsets, wire2label_type, "offset", "wire2label")?;

        reader.seek(SeekFrom::Start(wire2label_offset))?;

        let wire2label_size = find_section(&sec_sizes, wire2label_type, "size", "wire2label")?;

        let wire_mapping = read_map(&mut reader, wire2label_size, num_variables)?;

        let num_inputs = 1 + n_pub_in as usize + n_pub_out as usize;
        let num_aux = num_variables.checked_sub(num_inputs).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "fewer variables than public inputs and outputs",
            )
        })?;
        Ok(R1CS {
            num_aux,
            num_inputs,
            num_variables,
            constraints,
            wire_mapping: wire_mapping
                .iter()
                .map(|e| usize::try_from(*e))
                .collect::<std::result::Result<Vec<usize>, _>>()
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "wire id does not fit into usize")
                })?,
            n_pub_out,
            n_pub_in,
            n_prv_in,
            n_labels,
            n_constraints,
        })
    }
}

fn read_constraint_vec<R: Read, P: Pairing>(
    mut reader: R,
    n_wires: usize,
    field_size: usize,
) -> Result<ConstraintVec<P>> {
    let n_vec = reader.read_u32::<LittleEndian>()? as usize;
    // no preallocation, the count comes from the file
    let mut vec = Vec::new();
    for _ in 0..n_vec {
        let wire = reader.read_u32::<LittleEndian>()? as usize;
        if wire >= n_wires {
            Err(Error::new(
                ErrorKind::InvalidData,
                "wire index out of range",
            ))?;
        }
        vec.push((
            wire,
            reader_utils::prime_field_from_reader(&mut reader, field_size)?,
        ));
    }
    Ok(vec)
}

fn read_constraints<R: Read, P: Pairing>(
    mut reader: R,
    n_constraints: usize,
    n_wires: usize,
    field_size: usize,
) -> Result<Vec<Constraints<P>>> {
    // todo check section size
    let mut vec = Vec::new();
    for _ in 0..n_constraints {
        vec.push((
            read_constraint_vec::<_, P>(&mut reader, n_wires, field_size)?,
            read_constraint_vec::<_, P>(&mut reader, n_wires, field_size)?,
            read_constraint_vec::<_, P>(&mut reader, n_wires, field_size)?,
        ));
    }
    Ok(vec)
}

fn read_map<R: Read>(mut reader: R, size: u64, n_wires: usize) -> Result<Vec<u64>> {
    if size != u64::try_from(n_wires).expect("usize fits into u64") * 8 {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Invalid map section size",
        ))?;
    }
    let mut vec = Vec::new();
    for _ in 0..n_wires {
        vec.push(reader.read_u64::<LittleEndian>()?);
    }
    if vec.first() != Some(&0) {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Wire 0 should always be mapped to 0",
        ))?;
    }
    Ok(vec)
}

#[cfg(test)]
#[cfg(feature = "bls12-381")]
mod bls12_381_tests {

    use crate::tests::groth16_bls12_381_kats;
    use ark_bls12_381::Bls12_381;

    use super::*;

    use std::{fs::File, str::FromStr};

    #[test]
    fn test_bls_12_381_mult2() {
        let groth16_bls12_381_kats = groth16_bls12_381_kats();
        let r1cs_file = File::open(groth16_bls12_381_kats.join("circuit.r1cs")).unwrap();
        let r1cs = R1CS::<Bls12_381>::from_reader(r1cs_file).unwrap();
        assert_eq!(r1cs.num_inputs, 2);
        assert_eq!(r1cs.num_aux, 2);
        assert_eq!(r1cs.num_variables, 4);
        assert_eq!(r1cs.n_pub_out, 1);
        assert_eq!(r1cs.n_pub_in, 0);
        assert_eq!(r1cs.n_prv_in, 2);
        assert_eq!(r1cs.n_labels, 0x0004);
        assert_eq!(r1cs.n_constraints, 1);

        assert_eq!(r1cs.constraints.len(), 1);
        assert_eq!(r1cs.constraints[0].0.len(), 1);
        assert_eq!(r1cs.constraints[0].0[0].0, 2);
        assert_eq!(
            r1cs.constraints[0].0[0].1,
            ark_bls12_381::Fr::from_str(
                "52435875175126190479447740508185965837690552500527637822603658699938581184512"
            )
            .unwrap()
        );
        assert_eq!(r1cs.wire_mapping, vec![0, 1, 2, 3]);
    }
}

#[cfg(test)]
#[cfg(feature = "bn254")]
mod bn254_tests {
    use crate::tests::groth16_bn254_kats;

    use super::*;
    use ark_bn254::Bn254;

    use std::{fs::File, str::FromStr};
    #[test]
    fn test_bn254_mult2() {
        let groth16_bn254_kats = groth16_bn254_kats();
        let r1cs_file = File::open(groth16_bn254_kats.join("circuit.r1cs")).unwrap();
        let r1cs = R1CS::<Bn254>::from_reader(r1cs_file).unwrap();
        assert_eq!(r1cs.num_inputs, 2);
        assert_eq!(r1cs.num_aux, 2);
        assert_eq!(r1cs.num_variables, 4);
        assert_eq!(r1cs.n_pub_out, 1);
        assert_eq!(r1cs.n_pub_in, 0);
        assert_eq!(r1cs.n_prv_in, 2);
        assert_eq!(r1cs.n_labels, 0x0004);
        assert_eq!(r1cs.n_constraints, 1);

        assert_eq!(r1cs.constraints.len(), 1);
        assert_eq!(r1cs.constraints[0].0.len(), 1);
        assert_eq!(r1cs.constraints[0].0[0].0, 2);
        assert_eq!(
            r1cs.constraints[0].0[0].1,
            ark_bn254::Fr::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495616"
            )
            .unwrap()
        );
        assert_eq!(r1cs.wire_mapping, vec![0, 1, 2, 3]);
    }
}

#[cfg(test)]
#[cfg(feature = "bn254")]
mod malformed_bn254_tests {
    use ark_bn254::Bn254;

    use super::*;
    use crate::tests::{groth16_bn254_kats, patch_u32, section_offset};
    use std::io::Cursor;

    // header section layout for bn254: field_size, prime, then n_wires, ..., n_constraints
    const N_WIRES: usize = 4 + 32;
    const N_CONSTRAINTS: usize = N_WIRES + 4 * 4 + 8;

    fn parse_patched(patch: impl FnOnce(&mut [u8])) -> Result<R1CS<Bn254>> {
        let mut bytes = std::fs::read(groth16_bn254_kats().join("circuit.r1cs")).unwrap();
        patch(&mut bytes);
        R1CS::<Bn254>::from_reader(Cursor::new(bytes))
    }

    fn set_wire_map_len(bytes: &mut [u8], len: u64) {
        let len_pos = section_offset(bytes, 3) - 8;
        bytes[len_pos..len_pos + 8].copy_from_slice(&len.to_le_bytes());
    }

    #[test]
    fn rejects_huge_n_constraints() {
        parse_patched(|b| {
            let h = section_offset(b, 1);
            patch_u32(b, h + N_CONSTRAINTS, u32::MAX);
        })
        .expect_err("should fail");
    }

    #[test]
    fn rejects_huge_constraint_vec() {
        parse_patched(|b| {
            let s = section_offset(b, 2);
            patch_u32(b, s, u32::MAX);
        })
        .expect_err("should fail");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = std::fs::read(groth16_bn254_kats().join("circuit.r1cs")).unwrap();
        bytes.push(0);
        R1CS::<Bn254>::from_reader(Cursor::new(bytes)).expect_err("should fail");
    }

    #[test]
    fn rejects_out_of_range_wire() {
        // the constraint section starts with the length of the first vec, then its first wire
        let err = parse_patched(|b| {
            let s = section_offset(b, 2);
            patch_u32(b, s + 4, u32::MAX);
        })
        .expect_err("should fail");
        assert!(err.to_string().contains("wire index out of range"), "{err}");
    }

    #[test]
    fn rejects_huge_wire_map() {
        parse_patched(|b| {
            let h = section_offset(b, 1);
            patch_u32(b, h + N_WIRES, u32::MAX);
            set_wire_map_len(b, u64::from(u32::MAX) * 8);
        })
        .expect_err("should fail");
    }

    #[test]
    fn rejects_zero_wires() {
        parse_patched(|b| {
            let h = section_offset(b, 1);
            patch_u32(b, h + N_WIRES, 0);
            set_wire_map_len(b, 0);
        })
        .expect_err("should fail");
    }

    #[test]
    fn rejects_fewer_wires_than_inputs() {
        parse_patched(|b| {
            let h = section_offset(b, 1);
            patch_u32(b, h + N_WIRES, 1);
            set_wire_map_len(b, 8);
        })
        .expect_err("should fail");
    }
}
