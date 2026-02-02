use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{Groth16, r1cs_to_qap::LibsnarkReduction};
use ark_poly::EvaluationDomain;
use ark_relations::{
    lc,
    r1cs::{
        ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
        OptimizationGoal, SynthesisError,
    },
};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use criterion::{Criterion, criterion_group, criterion_main};
use rayon::iter::{
    IndexedParallelIterator as _, IntoParallelIterator as _, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator as _,
};

const NUM_CONSTRAINTS: usize = (1 << 16) - 100;
const NUM_VARIABLES: usize = (1 << 16) - 100;

/// This implementation is copied from [qap.rs](https://github.com/arkworks-rs/circom-compat/blob/master/src/circom/qap.rs) of `ark-circom@v0.5.0`.
/// As of Rust `v1.93`, `ark-circom` does not compile due to alignment issues.
// TODO Remove this code once `ark-circom` gets updated.
pub struct CircomReduction;

impl ark_groth16::r1cs_to_qap::R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        a[..num_constraints]
            .par_iter_mut()
            .zip(b[..num_constraints].par_iter_mut())
            .zip(matrices.a.par_iter())
            .zip(matrices.b.par_iter())
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = ark_groth16::r1cs_to_qap::evaluate_constraint(at_i, full_assignment);
                *b = ark_groth16::r1cs_to_qap::evaluate_constraint(bt_i, full_assignment);
            });

        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        let mut c = vec![zero; domain_size];
        c[..num_constraints]
            .par_iter_mut()
            .zip(&a)
            .zip(&b)
            .for_each(|((c_i, &a), &b)| {
                *c_i = a * b;
            });

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let root_of_unity = {
            let domain_size_double = 2 * domain_size;
            let domain_double =
                D::new(domain_size_double).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        ab.par_iter_mut()
            .zip(c)
            .for_each(|(ab_i, c_i)| *ab_i -= &c_i);

        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // the usual H query has domain-1 powers. Z has domain powers. So HZ has 2*domain-1 powers.
        let mut scalars = (0..2 * max_power + 1)
            .into_par_iter()
            .map(|i| delta_inverse * t.pow([i as u64]))
            .collect::<Vec<_>>();
        let domain_size = scalars.len();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        // generate the lagrange coefficients
        domain.ifft_in_place(&mut scalars);
        Ok(scalars.into_par_iter().skip(1).step_by(2).collect())
    }
}

#[derive(Copy, Clone)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

fn groth16_prove_bench<P: Pairing>(
    bench_name: &str,
    c: &mut Criterion,
    num_constraints: usize,
    num_variables: usize,
) {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let circuit = DummyCircuit::<P::ScalarField> {
        a: Some(P::ScalarField::rand(rng)),
        b: Some(P::ScalarField::rand(rng)),
        num_variables,
        num_constraints,
    };

    let (pk, _) = Groth16::<P>::circuit_specific_setup(circuit, rng).unwrap();
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    let prover = cs.borrow().unwrap();
    let full_assignment = [
        prover.instance_assignment.as_slice(),
        prover.witness_assignment.as_slice(),
    ]
    .concat();

    let mut group = c.benchmark_group(format!(
        "{bench_name} - {num_constraints} constraints - {num_variables} variables"
    ));
    let (r, s) = (P::ScalarField::rand(rng), P::ScalarField::rand(rng));

    let proof = Groth16::<P, CircomReduction>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        &full_assignment,
    )
    .unwrap();
    let proof2 = taceo_groth16::Groth16::<P>::prove::<taceo_groth16::CircomReduction>(
        &pk,
        r,
        s,
        &matrices,
        &full_assignment,
    )
    .unwrap();
    assert_eq!(proof, proof2);
    let proof = Groth16::<P>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        &full_assignment,
    )
    .unwrap();
    let proof2 = taceo_groth16::Groth16::<P>::prove::<taceo_groth16::LibSnarkReduction>(
        &pk,
        r,
        s,
        &matrices,
        &full_assignment,
    )
    .unwrap();
    assert_eq!(proof, proof2);

    group.bench_function("ark-groth16/CircomReduction", |b| {
        b.iter(|| {
            let _ = Groth16::<P, CircomReduction>::create_proof_with_reduction_and_matrices(
                &pk,
                r,
                s,
                &matrices,
                matrices.num_instance_variables,
                matrices.num_constraints,
                &full_assignment,
            )
            .unwrap();
        })
    });
    group.bench_function("ark-groth16/LibSnarkReduction", |b| {
        b.iter(|| {
            let _ = Groth16::<P>::create_proof_with_reduction_and_matrices(
                &pk,
                r,
                s,
                &matrices,
                matrices.num_instance_variables,
                matrices.num_constraints,
                &full_assignment,
            )
            .unwrap();
        })
    });
    group.bench_function("this-groth16/CircomReduction", |b| {
        b.iter(|| {
            let _ = taceo_groth16::Groth16::<P>::prove::<taceo_groth16::CircomReduction>(
                &pk,
                r,
                s,
                &matrices,
                &full_assignment,
            )
            .unwrap();
        })
    });
    group.bench_function("this-groth16/LibSnarkReduction", |b| {
        b.iter(|| {
            let _ = taceo_groth16::Groth16::<P>::prove::<taceo_groth16::LibSnarkReduction>(
                &pk,
                r,
                s,
                &matrices,
                &full_assignment,
            )
            .unwrap();
        })
    });
}

fn groth16_bench(c: &mut Criterion) {
    groth16_prove_bench::<ark_bn254::Bn254>("bn254", c, NUM_CONSTRAINTS, NUM_VARIABLES);
}

criterion_group!(benches, groth16_bench);
criterion_main!(benches);
