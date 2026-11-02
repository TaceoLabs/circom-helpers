use std::{
    io::{Cursor, Read},
    marker::PhantomData,
};

use ark_ec::pairing::Pairing;
use ark_serialize::SerializationError;
use byteorder::{LittleEndian, ReadBytesExt};
use thiserror::Error;

use crate::traits::CircomArkworksPairingBridge;

pub(crate) type ZkeyParserResult<T> = std::result::Result<T, ZkeyParserError>;

/// Circom zkey files have at most 14 sections (plonk).
const MAX_SECTIONS: usize = 32;

/// Error type describing errors during parsing zkey files
#[derive(Debug, Error)]
pub enum ZkeyParserError {
    /// Error during serialization
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    /// Error describing that an invalid modulus was found in the header for the chosen curve
    #[error("invalid modulus found in header for chosen curve")]
    InvalidPrimeInHeader,
    /// Unexpected Curve Size
    #[error("Unexpected field size for curve in header. Expected {0} but got {1}")]
    UnexpectedByteSize(u32, u32),
    /// Error during IO operations (reading/opening file, etc.)
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// generic bin file error
    #[error("bin file corrupted: \"{0}\"")]
    CorruptedBinFile(String),
}

#[derive(Debug)]
pub(crate) struct BinFile<P: Pairing + CircomArkworksPairingBridge> {
    #[expect(dead_code)]
    ftype: String,
    #[expect(dead_code)]
    version: u32,
    sections: Vec<Vec<u8>>,
    phantom_data: PhantomData<P>,
}

impl<P: Pairing + CircomArkworksPairingBridge> BinFile<P> {
    pub(crate) fn new<R: Read>(reader: &mut R) -> ZkeyParserResult<Self> {
        tracing::debug!("reading bin file");
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let ftype = std::str::from_utf8(&magic[..])
            .map_err(|_| ZkeyParserError::CorruptedBinFile("cannot parse magic number".to_owned()))?
            .to_string();
        tracing::debug!("file type for binfile: \"{ftype}\"");

        let version = reader.read_u32::<LittleEndian>()?;
        tracing::debug!("binfile version {}", version);

        let num_sections: usize = reader
            .read_u32::<LittleEndian>()?
            .try_into()
            .expect("u32 fits into usize");
        tracing::debug!("we got {} sections in binfile", num_sections);
        if num_sections > MAX_SECTIONS {
            return Err(ZkeyParserError::CorruptedBinFile(format!(
                "too many sections: {num_sections}"
            )));
        }
        let mut sections = vec![vec![]; num_sections];

        for _ in 0..num_sections {
            let section_id: usize = reader
                .read_u32::<LittleEndian>()?
                .try_into()
                .expect("u32 fits into usize");
            let section_length = reader.read_u64::<LittleEndian>()?;

            if section_id == 0 || section_id > num_sections {
                return Err(ZkeyParserError::CorruptedBinFile(format!(
                    "invalid section id {section_id}"
                )));
            }
            let section = &mut sections[section_id - 1];
            if !section.is_empty() {
                return Err(ZkeyParserError::CorruptedBinFile(
                    "sections are empty!".to_owned(),
                ));
            }
            // do not allocate based on the claimed length, only on what we actually read
            reader.by_ref().take(section_length).read_to_end(section)?;
            if section.len() as u64 != section_length {
                return Err(ZkeyParserError::CorruptedBinFile(format!(
                    "section {section_id} is shorter than its claimed length"
                )));
            }
        }
        tracing::debug!("successfully read bin file!");
        Ok(Self {
            ftype,
            version,
            sections,
            phantom_data: PhantomData::<P>,
        })
    }

    pub(crate) fn take_section(&mut self, id: usize) -> ZkeyParserResult<Cursor<Vec<u8>>> {
        self.take_section_raw(id).map(Cursor::new)
    }

    pub(crate) fn take_section_raw(&mut self, id: usize) -> ZkeyParserResult<Vec<u8>> {
        id.checked_sub(1)
            .and_then(|idx| self.sections.get_mut(idx))
            .map(std::mem::take)
            .ok_or_else(|| ZkeyParserError::CorruptedBinFile(format!("missing section {id}")))
    }
}

/// Checks that a section holds at least `count` elements of `elem_size` bytes. Used to validate
/// counts from the header before allocating based on them.
pub(crate) fn check_section_len(
    section_len: usize,
    count: usize,
    elem_size: usize,
    name: &str,
) -> ZkeyParserResult<()> {
    match count.checked_mul(elem_size) {
        Some(expected) if section_len >= expected => Ok(()),
        _ => Err(ZkeyParserError::CorruptedBinFile(format!(
            "section {name} ({section_len} bytes) is too short for {count} elements"
        ))),
    }
}

#[cfg(test)]
#[cfg(feature = "bn254")]
mod tests {
    use ark_bn254::Bn254;

    use super::BinFile;

    fn bin_file(n_sections: u32, sections: &[(u32, u64)]) -> Vec<u8> {
        let mut bytes = b"zkey".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&n_sections.to_le_bytes());
        for (id, len) in sections {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&len.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn rejects_huge_section_count() {
        let bytes = bin_file(u32::MAX, &[]);
        BinFile::<Bn254>::new(&mut bytes.as_slice()).expect_err("should fail");
    }

    #[test]
    fn rejects_section_longer_than_file() {
        let bytes = bin_file(1, &[(1, 1 << 40)]);
        BinFile::<Bn254>::new(&mut bytes.as_slice()).expect_err("should fail");
    }

    #[test]
    fn rejects_invalid_section_id() {
        for id in [0, 2, u32::MAX] {
            let bytes = bin_file(1, &[(id, 0)]);
            BinFile::<Bn254>::new(&mut bytes.as_slice()).expect_err("should fail");
        }
    }
}
