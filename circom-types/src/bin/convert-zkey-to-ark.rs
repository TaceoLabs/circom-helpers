use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

use ark_bn254::Bn254;
use ark_serialize::CanonicalSerialize;
use circom_types::groth16::ArkZkey;
use circom_types::{CheckElement, groth16::Zkey};
use clap::Parser;

fn install_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{
        EnvFilter,
        fmt::{self},
    };

    let fmt_layer = fmt::layer().with_target(false).with_line_number(false);
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

/// The configuration for the Zkey Conversion functionality.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct ZkeyConvertConfig {
    /// Path to the zkey.
    #[clap(long, env = "ZKEY_PATH")]
    pub zkey_path: PathBuf,

    /// Output path to the matrices file.
    #[clap(long, env = "MATRICES_PATH")]
    pub matrices_path: Option<PathBuf>,

    /// Output path to the proving key file.
    #[clap(long, env = "PROVING_KEY_PATH")]
    pub pk_path: Option<PathBuf>,

    /// Path to the ark-zkey file.
    #[clap(long, env = "ARKS_ZKEY_PATH", default_value = "arks.zkey")]
    pub arks_zkey_path: PathBuf,

    /// Use uncompressed serialization
    #[clap(long, env = "UNCOMPRESSED")]
    pub uncompressed: bool,
}

fn main() -> eyre::Result<()> {
    install_tracing();
    let config = ZkeyConvertConfig::parse();
    tracing::info!("Converting zkey at {}", config.zkey_path.display());
    let zkey = Zkey::<Bn254>::from_reader(
        BufReader::new(File::open(config.zkey_path)?),
        CheckElement::No,
    )?;
    tracing::info!("Loaded zkey");
    let ark_zkey = ArkZkey::from(zkey);
    tracing::info!("Converted zkey");
    let compress = if config.uncompressed {
        ark_serialize::Compress::No
    } else {
        ark_serialize::Compress::Yes
    };

    if let Some(matrices_path) = &config.matrices_path {
        ark_zkey
            .matrices
            .serialize_with_mode(BufWriter::new(File::create(matrices_path)?), compress)?;
        tracing::info!("Serialized matrices to {}", matrices_path.display());
    }

    if let Some(pk_path) = &config.pk_path {
        ark_zkey
            .pk
            .serialize_with_mode(File::create(pk_path)?, compress)?;
        tracing::info!("Serialized proving key to {}", pk_path.display());
    }

    ark_zkey.serialize_with_mode(File::create(&config.arks_zkey_path)?, compress)?;
    tracing::info!(
        "Serialized arks-zkey to {}",
        config.arks_zkey_path.display()
    );

    Ok(())
}
