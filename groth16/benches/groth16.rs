use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
        SynthesisError,
    },
};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use criterion::{Criterion, criterion_group, criterion_main};

const NUM_CONSTRAINTS: usize = (1 << 16) - 100;
const NUM_VARIABLES: usize = (1 << 16) - 100;

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

    let proof =
        Groth16::<P, ark_circom::CircomReduction>::create_proof_with_reduction_and_matrices(
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
            let _ = Groth16::<P, ark_circom::CircomReduction>::create_proof_with_reduction_and_matrices(
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
