use ark_ec::VariableBaseMSM;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, LegendreSymbol, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use std::marker::PhantomData;
use tracing::instrument;

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};
pub use ark_relations::r1cs::ConstraintMatrices;
pub use reduction::{CircomReduction, LibSnarkReduction, R1CSToQAP};

mod reduction;

macro_rules! rayon_join3 {
    ($t1: expr, $t2: expr, $t3: expr) => {{
        let ((x, y), z) = rayon::join(|| rayon::join($t1, $t2), $t3);
        (x, y, z)
    }};
}

macro_rules! rayon_join5 {
    ($t1: expr, $t2: expr, $t3: expr, $t4: expr, $t5: expr) => {{
        let ((((v, w), x), y), z) = rayon::join(
            || rayon::join(|| rayon::join(|| rayon::join($t1, $t2), $t3), $t4),
            $t5,
        );
        (v, w, x, y, z)
    }};
}
pub(crate) use rayon_join3;

/// Computes the roots of unity over the provided prime field. This method
/// is equivalent with [Circom's implementation](https://github.com/iden3/ffjavascript/blob/337b881579107ab74d5b2094dbe1910e33da4484/src/wasm_field1.js).
///
/// We calculate smallest quadratic non residue q (by checking q^((p-1)/2)=-1 mod p). We also calculate smallest t s.t. p-1=2^s*t, s is the two adicity.
/// We use g=q^t (this is a 2^s-th root of unity) as (some kind of) generator and compute another domain by repeatedly squaring g, should get to 1 in the s+1-th step.
/// Then if log2(\text{domain_size}) equals s we take q^2 as root of unity. Else we take the log2(\text{domain_size}) + 1-th element of the domain created above.
fn roots_of_unity<F: PrimeField + FftField>() -> (F, Vec<F>) {
    let mut roots = vec![F::zero(); F::TWO_ADICITY as usize + 1];
    let mut q = F::one();
    while q.legendre() != LegendreSymbol::QuadraticNonResidue {
        q += F::one();
    }
    let z = q.pow(F::TRACE);
    roots[0] = z;
    for i in 1..roots.len() {
        roots[i] = roots[i - 1].square();
    }
    roots.reverse();
    (q, roots)
}

/* old way of computing root of unity, does not work for bls12_381:
let root_of_unity = {
    let domain_size_double = 2 * domain_size;
    let domain_double =
        D::new(domain_size_double).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    domain_double.element(1)
};
new one is computed in the same way as in snarkjs (More precisely in ffjavascript/src/wasm_field1.js)
calculate smallest quadratic non residue q (by checking q^((p-1)/2)=-1 mod p) also calculate smallest t (F::TRACE) s.t. p-1=2^s*t, s is the two_adicity
use g=q^t (this is a 2^s-th root of unity) as (some kind of) generator and compute another domain by repeatedly squaring g, should get to 1 in the s+1-th step.
then if log2(domain_size) equals s we take as root of unity q^2, and else we take the log2(domain_size) + 1-th element of the domain created above
*/
#[instrument(level = "debug", name = "root of unity", skip_all)]
fn root_of_unity_for_groth16<F: PrimeField + FftField>(
    pow: usize,
    domain: &mut GeneralEvaluationDomain<F>,
) -> F {
    let (q, roots) = roots_of_unity::<F>();
    match domain {
        GeneralEvaluationDomain::Radix2(domain) => {
            domain.group_gen = roots[pow];
            domain.group_gen_inv = domain.group_gen.inverse().expect("can compute inverse");
        }
        GeneralEvaluationDomain::MixedRadix(domain) => {
            domain.group_gen = roots[pow];
            domain.group_gen_inv = domain.group_gen.inverse().expect("can compute inverse");
        }
    };
    if u64::from(F::TWO_ADICITY) == domain.log_size_of_group() {
        q.square()
    } else {
        roots[domain.log_size_of_group() as usize + 1]
    }
}

/// A Groth16 proof protocol.
///
/// This struct should never be initialized, it only provides associated functions [`Groth16::prove`] and [`Groth16::verify`].
pub struct Groth16<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> Groth16<P> {
    #[instrument(level = "debug", name = "Groth16 - Proof", skip_all)]
    pub fn prove<R: R1CSToQAP>(
        pkey: &ProvingKey<P>,
        r: P::ScalarField,
        s: P::ScalarField,
        matrices: &ConstraintMatrices<P::ScalarField>,
        witness: &[P::ScalarField],
    ) -> eyre::Result<Proof<P>> {
        let witness_len = witness.len();
        let witness_should_len = matrices.num_witness_variables + matrices.num_instance_variables;
        if witness_len != witness_should_len {
            eyre::bail!("expected witness len {witness_should_len}, got len {witness_len}",)
        }
        let h = R::witness_map_from_matrices::<P>(matrices, witness)?;
        let proof = Self::create_proof_with_assignment(
            pkey,
            r,
            s,
            h,
            witness,
            matrices.num_instance_variables,
        )?;
        Ok(proof)
    }

    fn calculate_coeff<C>(
        initial: C,
        query: &[C::Affine],
        vk_param: C::Affine,
        witness: &[P::ScalarField],
    ) -> C
    where
        C: CurveGroup<ScalarField = P::ScalarField>,
    {
        let acc = C::msm_unchecked(&query[1..], witness);
        let mut res = initial;
        res += query[0].into_group();
        res += vk_param.into_group();
        res += acc;
        res
    }

    #[instrument(level = "debug", name = "create proof with assignment", skip_all)]
    fn create_proof_with_assignment(
        pkey: &ProvingKey<P>,
        r: P::ScalarField,
        s: P::ScalarField,
        h: Vec<P::ScalarField>,
        witness: &[P::ScalarField],
        num_inputs: usize,
    ) -> eyre::Result<Proof<P>> {
        let delta_g1 = pkey.delta_g1.into_group();
        let alpha_g1 = pkey.vk.alpha_g1;
        let beta_g1 = pkey.beta_g1;
        let beta_g2 = pkey.vk.beta_g2;
        let delta_g2 = pkey.vk.delta_g2.into_group();

        let (r_g1, s_g1, s_g2, l_acc, h_acc) = rayon_join5!(
            || {
                let compute_a =
                    tracing::debug_span!("compute A in create proof with assignment").entered();
                // Compute A
                let r_g1 = delta_g1 * r;
                let r_g1 = Self::calculate_coeff(r_g1, &pkey.a_query, alpha_g1, &witness[1..]);
                compute_a.exit();
                r_g1
            },
            || {
                let compute_b =
                    tracing::debug_span!("compute B/G1 in create proof with assignment").entered();
                // Compute B in G1
                // In original implementation this is skipped if r==0, however r is shared in our case
                let s_g1 = delta_g1 * s;
                let s_g1 = Self::calculate_coeff(s_g1, &pkey.b_g1_query, beta_g1, &witness[1..]);
                compute_b.exit();
                s_g1
            },
            || {
                let compute_b =
                    tracing::debug_span!("compute B/G2 in create proof with assignment").entered();
                // Compute B in G2
                let s_g2 = delta_g2 * s;
                let s_g2 = Self::calculate_coeff(s_g2, &pkey.b_g2_query, beta_g2, &witness[1..]);
                compute_b.exit();
                s_g2
            },
            || {
                let msm_l_query = tracing::debug_span!("msm l_query").entered();
                let result = P::G1::msm_unchecked(&pkey.l_query, &witness[num_inputs..]);
                msm_l_query.exit();
                result
            },
            || {
                let msm_h_query = tracing::debug_span!("msm h_query").entered();
                //perform the msm for h
                let result = P::G1::msm_unchecked(&pkey.h_query, &h);
                msm_h_query.exit();
                result
            }
        );

        let rs = r * s;
        let r_s_delta_g1 = delta_g1 * rs;

        let g_a = r_g1;
        let g1_b = s_g1;

        let r_g1_b = g1_b * r;

        let s_g_a = g_a * s;

        let mut g_c = s_g_a;
        g_c += r_g1_b;
        g_c -= r_s_delta_g1;
        g_c += l_acc;

        g_c += h_acc;

        let g2_b = s_g2;

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        })
    }
}

impl<P: Pairing> Groth16<P> {
    /// Verify a Groth16 proof.
    /// This method is a wrapper arkworks Groth16 and does not use MPC.
    pub fn verify(
        vk: &VerifyingKey<P>,
        proof: &Proof<P>,
        public_inputs: &[P::ScalarField],
    ) -> eyre::Result<()> {
        let vk = ark_groth16::prepare_verifying_key(vk);
        let proof_valid = ark_groth16::Groth16::<P>::verify_proof(&vk, proof, public_inputs)
            .map_err(eyre::Report::from)?;
        if proof_valid {
            Ok(())
        } else {
            Err(eyre::eyre!("invalid proof"))
        }
    }
}
