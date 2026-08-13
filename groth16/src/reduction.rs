use ark_algebra::fft::{Domain, bit_reverse, powers};
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field, One};
use ark_relations::utils::matrix::Matrix;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use tracing::instrument;

use crate::ConstraintMatrices;
use crate::rayon_join3;

use super::groth16_roots_of_unity;

/// This trait is used to convert the witness into QAP witness as part of a Groth16 proof.
/// Refer to <https://docs.rs/ark-groth16/latest/ark_groth16/r1cs_to_qap/trait.R1CSToQAP.html> for more details.
/// We do not implement the other methods of the arkworks trait, as we do not need them during proof generation.
pub trait R1CSToQAP {
    /// Computes a QAP witness corresponding to the R1CS witness, using the provided `ConstraintMatrices`.
    fn witness_map_from_matrices<P: Pairing>(
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: &[P::ScalarField],
    ) -> eyre::Result<Vec<P::ScalarField>>;
}

/// The powers `[shift^0, shift^1, ..., shift^(size - 1)]`, permuted into bit-reversed order.
///
/// Both witness maps shift a polynomial onto a coset while its coefficients sit in bit-reversed
/// order (the output order of [`Domain::ifft_in_to_out`]), so the table has to be permuted the
/// same way. Building the table once and permuting it means the three coset shifts that follow
/// read it sequentially instead of jumping around it.
#[instrument(level = "debug", name = "bit reversed coset table", skip_all)]
fn bit_reversed_coset_table<F: FftField>(shift: F, size: usize) -> Vec<F> {
    let mut table = powers(shift, size);
    bit_reverse(&mut table);
    table
}

/// Shifts the polynomial given by natural-order evaluations onto the coset described by
/// `coset_table`, leaving the coset evaluations in natural order. The bit-reversal permutations
/// of the two half-transforms cancel.
fn evaluate_over_coset<F: FftField>(domain: &Domain<F>, values: &mut [F], coset_table: &[F]) {
    domain.ifft_in_to_out(values);
    mul_pointwise(values, coset_table);
    domain.fft_out_to_in(values);
}

fn mul_pointwise<F: Field>(values: &mut [F], factors: &[F]) {
    values
        .par_iter_mut()
        .zip_eq(factors.par_iter())
        .with_min_len(512)
        .for_each(|(value, factor)| *value *= factor);
}

/// Implements the witness map used by snarkjs. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain. snarkjs instead precomputes the Lagrange form of the powers of tau bases
/// in a domain twice as large and the witness map is computed as the odd coefficients of (AB-C)
/// in that domain. This serves as HZ when computing the C proof element.
///
/// Based on <https://github.com/arkworks-rs/circom-compat/>.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices<P: Pairing>(
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: &[P::ScalarField],
    ) -> eyre::Result<Vec<P::ScalarField>> {
        let num_constraints = matrices.num_constraints;
        let num_inputs = matrices.num_instance_variables;
        let domain_size = (num_constraints + num_inputs).next_power_of_two();
        let power = domain_size.ilog2() as usize;
        if power > P::ScalarField::TWO_ADICITY as usize {
            eyre::bail!("Polynomial Degree too large");
        }
        // snarkjs uses its own root of unity for the domain, and the root of unity of the domain
        // of twice the size as the coset shift.
        let (group_gen, coset_shift) = groth16_roots_of_unity::<P::ScalarField>(power);
        let domain = Domain::with_group_gen(domain_size, group_gen)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))?;

        let eval_constraint_span =
            tracing::debug_span!("evaluate constraints + coset table computation").entered();
        let (coset_table, mut a, mut b) = rayon_join3!(
            || bit_reversed_coset_table(coset_shift, domain_size),
            || {
                let eval_constraint_span_a =
                    tracing::debug_span!("evaluate constraints - a").entered();
                let mut result = evaluate_constraint::<P>(
                    domain_size,
                    &matrices.a,
                    matrices.num_constraints,
                    witness,
                );
                result[num_constraints..num_constraints + num_inputs]
                    .clone_from_slice(&witness[..num_inputs]);
                eval_constraint_span_a.exit();
                result
            },
            || {
                let eval_constraint_span_b =
                    tracing::debug_span!("evaluate constraints - b").entered();
                let result = evaluate_constraint::<P>(
                    domain_size,
                    &matrices.b,
                    matrices.num_constraints,
                    witness,
                );
                eval_constraint_span_b.exit();
                result
            }
        );
        eval_constraint_span.exit();

        // C = A * B over the original domain, computed before A and B move onto the coset so
        // that no clones of the evaluations are needed.
        let mul_span = tracing::debug_span!("c: mul vec").entered();
        let mut c = a
            .par_iter()
            .zip_eq(b.par_iter())
            .with_min_len(512)
            .map(|(a, b)| *a * b)
            .collect::<Vec<_>>();
        mul_span.exit();

        let coset_span = tracing::debug_span!("coset evaluations a/b/c (fft/ifft)").entered();
        rayon_join3!(
            || evaluate_over_coset(&domain, &mut a, &coset_table),
            || evaluate_over_coset(&domain, &mut b, &coset_table),
            || evaluate_over_coset(&domain, &mut c, &coset_table)
        );
        coset_span.exit();

        let compute_ab_span = tracing::debug_span!("compute ab").entered();
        a.par_iter_mut()
            .zip_eq(b.par_iter())
            .zip_eq(c.par_iter())
            .with_min_len(512)
            .for_each(|((a, b), c)| {
                *a *= *b;
                *a -= *c;
            });
        compute_ab_span.exit();
        Ok(a)
    }
}

fn evaluate_constraint<P: Pairing>(
    domain_size: usize,
    matrix: &Matrix<P::ScalarField>,
    num_constraints: usize,
    witness: &[P::ScalarField],
) -> Vec<P::ScalarField> {
    let mut result = matrix
        .par_iter()
        .take(num_constraints)
        .map(|lhs| {
            let mut acc = P::ScalarField::default();
            for (coeff, index) in lhs {
                acc += *coeff * witness[*index];
            }
            acc
        })
        .collect::<Vec<_>>();
    result.resize(domain_size, P::ScalarField::default());
    result
}

/// Implements the witness map used by libsnark. The arkworks witness map calculates the
/// coefficients of H through computing (AB-C)/Z in the evaluation domain and going back to the
/// coefficients domain.
///
/// Based on <https://github.com/arkworks-rs/groth16/>.
pub struct LibSnarkReduction;

impl R1CSToQAP for LibSnarkReduction {
    #[instrument(level = "debug", name = "witness map from matrices", skip_all)]
    fn witness_map_from_matrices<P: Pairing>(
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: &[P::ScalarField],
    ) -> eyre::Result<Vec<P::ScalarField>> {
        let num_constraints = matrices.num_constraints;
        let num_inputs = matrices.num_instance_variables;
        // Circom-generated matrices leave C empty (the zkey does not carry it); evaluating an
        // empty C would silently produce a wrong witness map.
        eyre::ensure!(
            matrices.c.len() >= num_constraints,
            "the C matrix is missing constraint rows; circom-generated matrices require CircomReduction"
        );
        let domain = Domain::<P::ScalarField>::new(num_constraints + num_inputs)
            .ok_or(eyre::eyre!("Polynomial Degree too large"))?;
        let domain_size = domain.size();

        let coset_table = bit_reversed_coset_table(P::ScalarField::GENERATOR, domain_size);

        let ((mut a, b), c) = rayon::join(
            || {
                rayon::join(
                    || {
                        let mut a = evaluate_constraint::<P>(
                            domain_size,
                            &matrices.a,
                            matrices.num_constraints,
                            witness,
                        );
                        a[num_constraints..num_constraints + num_inputs]
                            .clone_from_slice(&witness[..num_inputs]);
                        evaluate_over_coset(&domain, &mut a, &coset_table);
                        a
                    },
                    || {
                        let mut b = evaluate_constraint::<P>(
                            domain_size,
                            &matrices.b,
                            matrices.num_constraints,
                            witness,
                        );
                        evaluate_over_coset(&domain, &mut b, &coset_table);
                        b
                    },
                )
            },
            || {
                let mut c = evaluate_constraint::<P>(
                    domain_size,
                    &matrices.c,
                    matrices.num_constraints,
                    witness,
                );
                evaluate_over_coset(&domain, &mut c, &coset_table);
                c
            },
        );

        let vanishing_polynomial_over_coset = (P::ScalarField::GENERATOR.pow([domain_size as u64])
            - P::ScalarField::one())
        .inverse()
        .expect("Inverse exists");

        a.par_iter_mut()
            .zip_eq(b.par_iter())
            .zip_eq(c.par_iter())
            .with_min_len(512)
            .for_each(|((a, b), c)| {
                *a *= *b;
                *a -= *c;
                *a *= vanishing_polynomial_over_coset;
            });

        // Interpolate over the coset and undo the shift. `ifft_in_to_out` leaves the
        // coefficients in bit-reversed order, so permute them back before applying the inverse
        // shift, which then reads its table sequentially.
        domain.ifft_in_to_out(&mut a);
        bit_reverse(&mut a);
        let shift_inv = P::ScalarField::GENERATOR
            .inverse()
            .expect("generator has always inverse");
        mul_pointwise(&mut a, &powers(shift_inv, domain_size));

        Ok(a)
    }
}
