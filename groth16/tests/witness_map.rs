//! Tests the DIF/DIT-based witness maps against reference implementations built on
//! [`ark_poly::GeneralEvaluationDomain`] (the implementation this crate used before switching to
//! `taceo-ark-algebra`), and the full prover against `ark-groth16`.

use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ff::{FftField, Field, PrimeField, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
        R1CS_PREDICATE_LABEL, SynthesisError,
    },
    lc,
};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use taceo_groth16::{
    CircomReduction, ConstraintMatrices, Groth16, LibSnarkReduction, R1CSToQAP,
    groth16_roots_of_unity,
};

const NUM_CONSTRAINTS: usize = 4000;
const NUM_VARIABLES: usize = 4100;

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
            cs.enforce_r1cs_constraint(|| lc!() + a, || lc!() + b, || lc!() + c)?;
        }

        cs.enforce_r1cs_constraint(|| lc!(), || lc!(), || lc!())?;

        Ok(())
    }
}

struct TestSetup<P: Pairing> {
    pk: ark_groth16::ProvingKey<P>,
    vk: ark_groth16::VerifyingKey<P>,
    matrices: ConstraintMatrices<P::ScalarField>,
    ark_matrices: Vec<ark_relations::utils::matrix::Matrix<P::ScalarField>>,
    full_assignment: Vec<P::ScalarField>,
    num_inputs: usize,
    num_constraints: usize,
}

fn setup<P: Pairing>() -> TestSetup<P> {
    let rng = &mut StdRng::seed_from_u64(0);
    let circuit = DummyCircuit::<P::ScalarField> {
        a: Some(P::ScalarField::rand(rng)),
        b: Some(P::ScalarField::rand(rng)),
        num_variables: NUM_VARIABLES,
        num_constraints: NUM_CONSTRAINTS,
    };

    let (pk, vk) = ark_groth16::Groth16::<P>::circuit_specific_setup(circuit, rng).unwrap();
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    cs.finalize();
    let cs_matrices = cs.to_matrices().unwrap();
    let ark_matrices = cs_matrices
        .get(R1CS_PREDICATE_LABEL)
        .expect("R1CS predicate registered on a default ConstraintSystem")
        .clone();
    let num_inputs = cs.num_instance_variables();
    let num_constraints = cs.num_constraints();
    let matrices = ConstraintMatrices {
        num_instance_variables: num_inputs,
        num_witness_variables: cs.num_witness_variables(),
        num_constraints,
        a_num_non_zero: ark_matrices[0].iter().map(Vec::len).sum(),
        b_num_non_zero: ark_matrices[1].iter().map(Vec::len).sum(),
        c_num_non_zero: ark_matrices[2].iter().map(Vec::len).sum(),
        a: ark_matrices[0].clone(),
        b: ark_matrices[1].clone(),
        c: ark_matrices[2].clone(),
    };
    let prover = cs.borrow().unwrap();
    let full_assignment = [
        prover.instance_assignment().unwrap(),
        prover.witness_assignment().unwrap(),
    ]
    .concat();

    TestSetup {
        pk,
        vk,
        matrices,
        ark_matrices,
        full_assignment,
        num_inputs,
        num_constraints,
    }
}

fn evaluate_constraints<F: PrimeField>(
    matrices: &ConstraintMatrices<F>,
    witness: &[F],
    domain_size: usize,
) -> (Vec<F>, Vec<F>, Vec<F>) {
    let evaluate = |matrix: &ark_relations::utils::matrix::Matrix<F>| {
        let mut result = matrix
            .iter()
            .take(matrices.num_constraints)
            .map(|lhs| {
                lhs.iter()
                    .map(|(coeff, index)| *coeff * witness[*index])
                    .sum()
            })
            .collect::<Vec<F>>();
        result.resize(domain_size, F::zero());
        result
    };
    let mut a = evaluate(&matrices.a);
    let b = evaluate(&matrices.b);
    let c = evaluate(&matrices.c);
    let num_constraints = matrices.num_constraints;
    let num_inputs = matrices.num_instance_variables;
    a[num_constraints..num_constraints + num_inputs].clone_from_slice(&witness[..num_inputs]);
    (a, b, c)
}

/// The circom witness map as this crate implemented it before `taceo-ark-algebra`: ark-poly
/// transforms over a domain with the snarkjs generator, and the coset shift applied in natural
/// order.
fn reference_circom_witness_map<P: Pairing>(
    matrices: &ConstraintMatrices<P::ScalarField>,
    witness: &[P::ScalarField],
) -> Vec<P::ScalarField> {
    let domain_size =
        (matrices.num_constraints + matrices.num_instance_variables).next_power_of_two();
    let power = domain_size.ilog2() as usize;
    let (group_gen, coset_shift) = groth16_roots_of_unity::<P::ScalarField>(power);
    let mut domain = Radix2EvaluationDomain::<P::ScalarField>::new(domain_size).unwrap();
    domain.group_gen = group_gen;
    domain.group_gen_inv = group_gen.inverse().unwrap();

    let mut shift_powers = Vec::with_capacity(domain_size);
    let mut current = P::ScalarField::ONE;
    for _ in 0..domain_size {
        shift_powers.push(current);
        current *= coset_shift;
    }

    let (a, b, _) = evaluate_constraints(matrices, witness, domain_size);
    let shift_onto_coset = |values: &mut Vec<P::ScalarField>| {
        domain.ifft_in_place(values);
        for (value, power) in values.iter_mut().zip(&shift_powers) {
            *value *= power;
        }
        domain.fft_in_place(values);
    };

    let mut a_coset = a.clone();
    let mut b_coset = b.clone();
    shift_onto_coset(&mut a_coset);
    shift_onto_coset(&mut b_coset);

    let mut c = a.iter().zip(&b).map(|(a, b)| *a * b).collect::<Vec<_>>();
    shift_onto_coset(&mut c);

    a_coset
        .iter()
        .zip(&b_coset)
        .zip(&c)
        .map(|((a, b), c)| *a * b - c)
        .collect()
}

/// The libsnark witness map as this crate implemented it before `taceo-ark-algebra`, built on
/// ark-poly's coset domains.
fn reference_libsnark_witness_map<P: Pairing>(
    matrices: &ConstraintMatrices<P::ScalarField>,
    witness: &[P::ScalarField],
) -> Vec<P::ScalarField> {
    let domain = GeneralEvaluationDomain::<P::ScalarField>::new(
        matrices.num_constraints + matrices.num_instance_variables,
    )
    .unwrap();
    let coset_domain = domain.get_coset(P::ScalarField::GENERATOR).unwrap();

    let (mut a, mut b, mut c) = evaluate_constraints(matrices, witness, domain.size());
    for values in [&mut a, &mut b, &mut c] {
        domain.ifft_in_place(values);
        coset_domain.fft_in_place(values);
    }

    let vanishing_polynomial_over_coset = domain
        .evaluate_vanishing_polynomial(P::ScalarField::GENERATOR)
        .inverse()
        .unwrap();

    let mut ab = a
        .iter()
        .zip(&b)
        .zip(&c)
        .map(|((a, b), c)| (*a * b - c) * vanishing_polynomial_over_coset)
        .collect::<Vec<_>>();
    coset_domain.ifft_in_place(&mut ab);
    ab
}

fn witness_maps_match_reference<P: Pairing>() {
    let s = setup::<P>();

    let actual =
        CircomReduction::witness_map_from_matrices::<P>(&s.matrices, &s.full_assignment).unwrap();
    let expected = reference_circom_witness_map::<P>(&s.matrices, &s.full_assignment);
    assert_eq!(actual, expected, "CircomReduction");

    let actual =
        LibSnarkReduction::witness_map_from_matrices::<P>(&s.matrices, &s.full_assignment).unwrap();
    let expected = reference_libsnark_witness_map::<P>(&s.matrices, &s.full_assignment);
    assert_eq!(actual, expected, "LibSnarkReduction");
}

fn proof_matches_ark_groth16<P, C1, C2>()
where
    P: Pairing<
            G1 = Projective<C1>,
            G1Affine = Affine<C1>,
            G2 = Projective<C2>,
            G2Affine = Affine<C2>,
        >,
    C1: SWCurveConfig<ScalarField = P::ScalarField>,
    C2: SWCurveConfig<ScalarField = P::ScalarField>,
{
    let s = setup::<P>();
    let rng = &mut StdRng::seed_from_u64(1);
    let (r, sv) = (P::ScalarField::rand(rng), P::ScalarField::rand(rng));

    let expected =
        ark_groth16::Groth16::<P, LibsnarkReduction>::create_proof_with_reduction_and_matrices(
            &s.pk,
            r,
            sv,
            &s.ark_matrices,
            s.num_inputs,
            s.num_constraints,
            &s.full_assignment,
        )
        .unwrap();
    let actual =
        Groth16::<P>::prove::<LibSnarkReduction>(&s.pk, r, sv, &s.matrices, &s.full_assignment)
            .unwrap();
    assert_eq!(actual, expected);

    Groth16::<P>::verify(&s.vk, &actual, &s.full_assignment[1..s.num_inputs]).unwrap();
}

#[test]
fn witness_maps_match_reference_bn254() {
    witness_maps_match_reference::<ark_bn254::Bn254>();
}

#[test]
fn witness_maps_match_reference_bls12_381() {
    witness_maps_match_reference::<ark_bls12_381::Bls12_381>();
}

#[test]
fn proof_matches_ark_groth16_bn254() {
    proof_matches_ark_groth16::<ark_bn254::Bn254, _, _>();
}

#[test]
fn proof_matches_ark_groth16_bls12_381() {
    proof_matches_ark_groth16::<ark_bls12_381::Bls12_381, _, _>();
}
