use ark_bn254::Bn254;
use ark_ff::Zero;
use circom_types::groth16::{Proof, PublicInput, VerificationKey};
use clap::{Args, Parser, Subcommand};
use eyre::Context;
use std::{fs::File, path::PathBuf, process::ExitCode};
use taceo_groth16_sol::askama::Template;
use taceo_groth16_sol::{SolidityVerifierConfig, SolidityVerifierContext};

/// Utility tools for creating and interacting with Solidity verifier contracts for BN254 Groth16 proofs. This CLI can extract a Solidity verifier from a verification key (based on the Groth16 implementation in gnark) and generate parameters for calling both the compressed and uncompressed versions of the verifier contract.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Config {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Debug, Subcommand)]
enum SubCommand {
    GenerateCall(GenerateCallConfig),
    ExtractVerifier(ExtractVerifierConfig),
}

#[derive(Debug, Default, Args)]
struct GenerateCallConfig {
    /// Path to Circom proof.
    #[clap(long)]
    pub proof: PathBuf,
    /// Path to Circom public inputs.
    #[clap(long)]
    pub public: PathBuf,
    /// Output of the Solidity file. Write to stdout if omitted.
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    /// If set, will use uncompressed points. Compressed are better when interacting with L2.
    #[clap(long)]
    pub uncompressed: bool,
}

#[derive(Debug, Default, Args)]
struct ExtractVerifierConfig {
    /// Path to Circom verification key.
    #[clap(short, long)]
    pub vk: PathBuf,
    /// Output of the Solidity file. Write to stdout if omitted.
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    /// The pragma version of the Solidity contract.
    #[clap(long, default_value = "^0.8.0")]
    pub pragma_version: String,
}

fn generate_call(config: GenerateCallConfig) -> eyre::Result<ExitCode> {
    let GenerateCallConfig {
        proof,
        public,
        output,
        uncompressed,
    } = config;
    let proof: Proof<Bn254> = serde_json::from_reader(File::open(proof)?)?;
    let public_input: PublicInput<ark_bn254::Fr> = serde_json::from_reader(File::open(public)?)?;

    let pub_ins = public_input
        .0
        .into_iter()
        .map(|x| {
            if x.is_zero() {
                "0".to_owned()
            } else {
                x.to_string()
            }
        })
        .collect::<Vec<String>>()
        .join(",");

    let proof = if uncompressed {
        taceo_groth16_sol::prepare_uncompressed_proof(&proof.into())
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",")
    } else {
        taceo_groth16_sol::prepare_compressed_proof(&proof.into())
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",")
    };
    let result = format!("[{proof}],[{pub_ins}]");
    if let Some(output) = output {
        std::fs::write(output, result)?;
    } else {
        println!("{result}");
    }
    Ok(ExitCode::SUCCESS)
}

fn extract_verifier(config: ExtractVerifierConfig) -> eyre::Result<ExitCode> {
    let ExtractVerifierConfig {
        vk,
        output,
        pragma_version,
    } = config;
    let vk =
        VerificationKey::<Bn254>::from_reader(File::open(vk).context("while opening input file")?)
            .context("while parsing verification-key")?;

    let contract = SolidityVerifierContext {
        vk: vk.into(),
        config: SolidityVerifierConfig { pragma_version },
    };
    let rendered = contract.render().unwrap();
    if let Some(output) = output {
        std::fs::write(output, rendered).context("while writing output")?;
    } else {
        println!("{rendered}")
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> eyre::Result<ExitCode> {
    let config = Config::parse();
    match config.subcommand {
        SubCommand::GenerateCall(config) => generate_call(config),
        SubCommand::ExtractVerifier(config) => extract_verifier(config),
    }
}
