# ark-serde-compat

Various serialization helpers for serializing `arkworks` types as strings using `serde`.

## Overview

This crate provides serde-compatible serialization and deserialization functions for arkworks-rs types, designed to work seamlessly with circom's JSON format expectations. Field elements are serialized as decimal strings, and curve points are serialized as arrays of coordinate strings.

## Features

- `bn254` (default): Enables serialization support for BN254 curve types
- `babyjubjub` (default): Enables serialization support for BabyJubJub curve types

## Usage

Use the provided functions with serde's field attributes:

```rust
use serde::{Serialize, Deserialize};
use ark_bn254::{Fr, G1Affine};

#[derive(Serialize, Deserialize)]
struct MyStruct {
    #[serde(serialize_with = "taceo_ark_serde_compat::bn254::serialize_fr")]
    #[serde(deserialize_with = "taceo_ark_serde_compat::bn254::deserialize_fr")]
    scalar: Fr,

    #[serde(serialize_with = "taceo_ark_serde_compat::bn254::serialize_g1")]
    #[serde(deserialize_with = "taceo_ark_serde_compat::bn254::deserialize_g1")]
    point: G1Affine,
}
```

## Serialization Formats

### Field Elements
Field elements (Fr, Fq) are serialized as decimal strings:
```json
"12345678901234567890"
```

### BN254 G1 Points
G1 points are serialized in projective coordinates `[x, y, z]`:
```json
["1", "2", "1"]
```

The point at infinity is represented as:
```json
["0", "1", "0"]
```

### BN254 G2 Points
G2 points are serialized as `[[x0, x1], [y0, y1], [z0, z1]]`:
```json
[["1", "2"], ["3", "4"], ["1", "0"]]
```

### BabyJubJub Points
BabyJubJub points are serialized in affine coordinates `[x, y]`:
```json
["123", "456"]
```

## License

See the repository LICENSE file for details.
