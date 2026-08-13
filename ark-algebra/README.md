# ark-algebra

Optimized multi-scalar multiplication (MSM) and FFT routines for [arkworks-rs](https://arkworks.rs) curves and fields.

## Overview

This crate provides drop-in alternatives to `ark_ec::VariableBaseMSM` and `ark_poly::GeneralEvaluationDomain` that are tuned for SNARK provers, where the same domain is transformed many times in a row and several MSMs run concurrently:

- **`fft`**: Radix-2 FFTs with the twiddle factors precomputed once per domain and the two half-transforms (DIF/DIT) exposed separately, so chained transforms skip the bit-reversal permutation entirely. The transforms are generic over [`ark_poly::domain::DomainCoeff`], so they also work on secret-shared coefficients (as used in [co-snarks](https://github.com/TaceoLabs/co-snarks)).
- **`msm`**: A signed-digit bucket MSM that parallelizes only over windows (instead of over the whole Rayon pool, which degrades when several MSMs run concurrently) and accumulates large windows in affine coordinates with batch inversions, as gnark-crypto does. It is generic over `ark_ec::short_weierstrass::SWCurveConfig`, since the batch-affine accumulation has to construct points from raw coordinates.

Both modules are tested against their arkworks counterparts.

## Usage

```rust
use taceo_ark_algebra::{fft::Domain, msm};
use ark_bn254::{Fr, G1Projective};

// FFT: interpolate and re-evaluate without bit-reversal permutations.
let domain = Domain::<Fr>::new(1024).unwrap();
let mut values: Vec<Fr> = /* evaluations */;
domain.ifft_in_to_out(&mut values); // natural order in, bit-reversed out
domain.fft_out_to_in(&mut values);  // bit-reversed in, natural order out

// MSM (the curve config is inferred from the affine bases)
let result: G1Projective = msm::msm_unchecked(&bases, &scalars);
```
