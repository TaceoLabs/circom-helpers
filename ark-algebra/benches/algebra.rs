//! Benchmarks of this crate's MSM and FFT against their arkworks counterparts.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, UniformRand};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use taceo_ark_algebra::{fft, msm};

fn random_bases(size: usize, rng: &mut StdRng) -> Vec<G1Affine> {
    let projective = (0..size)
        .map(|_| G1Projective::rand(rng))
        .collect::<Vec<_>>();
    G1Projective::normalize_batch(&projective)
}

fn msm_bench(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let mut group = c.benchmark_group("msm/bn254-g1");
    for log_size in [14, 16, 18] {
        let size = 1usize << log_size;
        let bases = random_bases(size, &mut rng);
        let scalars = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        group.bench_function(BenchmarkId::new("ark-ec", format!("2^{log_size}")), |b| {
            b.iter(|| G1Projective::msm_unchecked(&bases, &scalars))
        });
        group.bench_function(
            BenchmarkId::new("taceo-ark-algebra", format!("2^{log_size}")),
            |b| b.iter(|| msm::msm_unchecked(&bases, &scalars)),
        );
    }
    group.finish();
}

fn fft_bench(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(1);
    let mut group = c.benchmark_group("fft/bn254-fr");
    for log_size in [16, 20] {
        let size = 1usize << log_size;
        let values = (0..size).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let ark = Radix2EvaluationDomain::<Fr>::new(size).unwrap();
        let ark_coset = ark.get_coset(Fr::GENERATOR).unwrap();
        let domain = fft::Domain::<Fr>::new(size).unwrap();
        let coset_table = {
            let mut table = fft::powers(Fr::GENERATOR, size);
            fft::bit_reverse(&mut table);
            table
        };

        // A single forward transform with natural-order output. Ours pays an explicit
        // bit-reversal here; chained transforms below avoid it.
        group.bench_function(
            BenchmarkId::new("ark-ec/fft", format!("2^{log_size}")),
            |b| {
                b.iter_batched_ref(
                    || values.clone(),
                    |values| ark.fft_in_place(values),
                    BatchSize::LargeInput,
                )
            },
        );
        group.bench_function(
            BenchmarkId::new("taceo-ark-algebra/fft", format!("2^{log_size}")),
            |b| {
                b.iter_batched_ref(
                    || values.clone(),
                    |values| {
                        domain.fft_in_to_out(values);
                        fft::bit_reverse(values);
                    },
                    BatchSize::LargeInput,
                )
            },
        );

        // The Groth16 pattern: interpolate, shift onto a coset, evaluate. The DIF/DIT chain
        // needs no permutation at all.
        group.bench_function(
            BenchmarkId::new("ark-ec/coset-eval", format!("2^{log_size}")),
            |b| {
                b.iter_batched_ref(
                    || values.clone(),
                    |values| {
                        ark.ifft_in_place(values);
                        ark_coset.fft_in_place(values);
                    },
                    BatchSize::LargeInput,
                )
            },
        );
        group.bench_function(
            BenchmarkId::new("taceo-ark-algebra/coset-eval", format!("2^{log_size}")),
            |b| {
                b.iter_batched_ref(
                    || values.clone(),
                    |values| {
                        domain.ifft_in_to_out(values);
                        values
                            .par_iter_mut()
                            .zip_eq(coset_table.par_iter())
                            .with_min_len(512)
                            .for_each(|(value, factor)| *value *= factor);
                        domain.fft_out_to_in(values);
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
    group.finish();
}

criterion_group!(benches, msm_bench, fft_bench);
criterion_main!(benches);
