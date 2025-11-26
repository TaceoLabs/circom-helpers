# ark-serde-compat

Various serialization helpers for serializing `arkworks` types using `serde`.

## Overview

This crate provides serde-compatible serialization and deserialization functions for arkworks-rs types, supporting both human-readable and non-human readable formats:

- **Human-readable formats** (e.g., JSON): Field elements are serialized as decimal strings, and curve points are serialized as arrays of coordinate strings. This format is designed to work seamlessly with Circom's JSON format expectations.
- **Non-human readable formats** (e.g., bincode, CBOR): Uses `ark-serialize` with **compressed mode** for efficient binary serialization.

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

### Human-Readable Formats (JSON)

#### Field Elements
Field elements (Fr, Fq) are serialized as decimal strings:
```json
"12345678901234567890"
```

#### BN254 G1 Points
G1 points are serialized in projective coordinates `[x, y, z]`:
```json
["1", "2", "1"]
```

The point at infinity is represented as:
```json
["0", "1", "0"]
```

#### BN254 G2 Points
G2 points are serialized as `[[x0, x1], [y0, y1], [z0, z1]]`:
```json
[["1", "2"], ["3", "4"], ["1", "0"]]
```

#### BabyJubJub Points
BabyJubJub points are serialized in affine coordinates `[x, y]`:
```json
["123", "456"]
```

### Non-Human Readable Formats (Binary)

For non-human readable serializers like bincode and CBOR, all arkworks types are serialized using `ark-serialize` in **compressed mode**. This provides efficient binary serialization that is significantly more compact than the JSON representation.

The same serde attributes work for both human-readable and non-human readable formats:

```rust
use serde::{Serialize, Deserialize};
use ark_bn254::Fr;

#[derive(Serialize, Deserialize)]
struct MyStruct {
    #[serde(serialize_with = "taceo_ark_serde_compat::serialize_f")]
    #[serde(deserialize_with = "taceo_ark_serde_compat::deserialize_f")]
    field: Fr,
}

// Example usage
let my_struct = MyStruct { field: Fr::from(42u64) };

// Works with JSON
let json = serde_json::to_string(&my_struct)?;

// Also works with bincode (uses compressed ark-serialize)
let binary = bincode::serde::encode_to_vec(&my_struct, bincode::config::standard())?;
```

## License

See the repository LICENSE file for details.
