use ark_ec::AffineRepr;
use ark_groth16::VerifyingKey;
use askama::Template;

#[derive(Template)]
#[template(path = "../templates/bn254_verifier.sol", escape = "none")]
pub struct SolidityVerifierContext {
    pub vk: VerifyingKey<ark_bn254::Bn254>,
    pub config: SolidityVerifierConfig,
}

pub struct SolidityVerifierConfig {
    pub pragma_version: String,
}

impl Default for SolidityVerifierConfig {
    fn default() -> Self {
        Self {
            pragma_version: "^0.8.0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use askama::Template;
    use taceo_circom_types::groth16::VerificationKey;

    const TEST_VK_BN254: &str = include_str!("../data/test_verification_key.json");
    const TEST_GNARK_OUTPUT: &str = include_str!("../data/gnark_output.txt");

    #[test]
    fn test() {
        let config = super::SolidityVerifierConfig::default();
        let vk = serde_json::from_str::<VerificationKey<ark_bn254::Bn254>>(TEST_VK_BN254).unwrap();
        let contract = super::SolidityVerifierContext {
            vk: vk.into(),
            config,
        };

        let rendered = contract.render().unwrap();
        // Askama supresses trailing newlines, so we add one for comparison
        let rendered = format!("{}\n", rendered);
        assert_eq!(rendered, TEST_GNARK_OUTPUT);
    }
}
