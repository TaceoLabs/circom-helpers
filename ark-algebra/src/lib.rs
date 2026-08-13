//! Optimized multi-scalar multiplication and FFT routines for
//! [arkworks-rs](https://arkworks.rs) curves and fields.
//!
//! See the [`fft`] and [`msm`] module documentation for how and why the implementations differ
//! from their arkworks counterparts.

pub mod fft;
pub mod msm;
