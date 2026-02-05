# Changelog

## [Unreleased]

## [0.2.1](https://github.com/TaceoLabs/circom-helpers/compare/taceo-groth16-sol-v0.2.0...taceo-groth16-sol-v0.2.1)

### Build


- *(deps)* Update askama requirement from 0.14.0 to 0.15.4 ([#30](https://github.com/TaceoLabs/circom-helpers/pull/30)) - ([837083f](https://github.com/TaceoLabs/circom-helpers/commit/837083f50039e371aada0da8bc0f21f1d3d9eced))


## [0.2.0](https://github.com/TaceoLabs/circom-helpers/compare/taceo-groth16-sol-v0.1.0...taceo-groth16-material-v0.2.0)

### Build


- *(deps)* Update `taceo_circom_types` to v0.2.0, potentially breaking serialization if values were serialized non-canonically.

## [0.1.0]

### ⛰️ Features


- Add gnark-sol-extractor binary ([#24](https://github.com/TaceoLabs/circom-helpers/pull/24)) - ([198ac8f](https://github.com/TaceoLabs/circom-helpers/commit/198ac8f3fa5349ba69133446509f64df5e2d1caa))
- Add functions to prepare groth16 proofs for Solidity calls - ([3589705](https://github.com/TaceoLabs/circom-helpers/commit/35897056513ddebffd09a144a3f52e4bac9fb82f))
- Enable rendering template and add a test for equality of output - ([2a045ce](https://github.com/TaceoLabs/circom-helpers/commit/2a045ce7dfdb9e6808f7822a1d9edb24dccc5f84))

### 🚜 Refactor


- Convert go template syntax to Rinja template syntax for askama - ([475037d](https://github.com/TaceoLabs/circom-helpers/commit/475037d986868f96097176060132751285d871fd))
- Remove all instances of committed public inputs from template - ([c59ccb0](https://github.com/TaceoLabs/circom-helpers/commit/c59ccb0d59cb3d072486bfe63d39a3f9f35dbc05))

### 📚 Documentation


- Add crate keywords and description + Readme ([#23](https://github.com/TaceoLabs/circom-helpers/pull/23)) - ([6cce030](https://github.com/TaceoLabs/circom-helpers/commit/6cce0301b60d03644a1658e9cd41f5bf1a69f134))
- Add documentation for panics - ([0e225b4](https://github.com/TaceoLabs/circom-helpers/commit/0e225b404a939f772e06c3eb2755d92ba13a6835))
- Add documentation for groth16-sol crate - ([3ac8337](https://github.com/TaceoLabs/circom-helpers/commit/3ac8337f2de4117f630245dd895ab523b645eddf))
- Add the Audit report for gnark verifier as a reference - ([fbf0469](https://github.com/TaceoLabs/circom-helpers/commit/fbf0469ef14218773702fbaaf2ff4a56c7bb31ae))

### ⚙️ Miscellaneous Tasks


- Exclude data folder from publish - ([443f52c](https://github.com/TaceoLabs/circom-helpers/commit/443f52c65f2caca171ffc0d79f109ac856b579f8))
- Import unmodified Solidity verifier go template - ([7ccf3c2](https://github.com/TaceoLabs/circom-helpers/commit/7ccf3c2fa1f75d42236ef8b5e08e3c70b2d135bc))
- Add new crate skeleton for groth16-sol - ([ff75188](https://github.com/TaceoLabs/circom-helpers/commit/ff75188080f68304b56fc36529c6bb1525e1c4a8))

### Build


- Feature-gate template behind a default feature - ([989a31a](https://github.com/TaceoLabs/circom-helpers/commit/989a31abaa467bbf3675b747dbc8283599088dde))

