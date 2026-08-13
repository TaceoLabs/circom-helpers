use ark_algebra::msm::msm_unchecked;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{FftField, Field, LegendreSymbol, PrimeField};
use ark_relations::utils::matrix::Matrix;
use std::marker::PhantomData;
use tracing::instrument;

pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};
pub use reduction::{CircomReduction, LibSnarkReduction, R1CSToQAP};

mod reduction;

/// The R1CS matrices for a constraint system, together with the variable and
/// constraint counts. This mirrors the `ark_relations::r1cs::ConstraintMatrices`
/// struct that was removed in `ark-relations` 0.6 (which only exposes a
/// `BTreeMap<Label, Vec<Matrix<F>>>` from `ConstraintSystem::to_matrices`).
#[derive(Clone, Debug)]
pub struct ConstraintMatrices<F: Field> {
    /// The number of variables that are "public instances" to the constraint
    /// system.
    pub num_instance_variables: usize,
    /// The number of variables that are "private witnesses" to the constraint
    /// system.
    pub num_witness_variables: usize,
    /// The number of constraints in the constraint system.
    pub num_constraints: usize,
    /// The number of non_zero entries in the A matrix.
    pub a_num_non_zero: usize,
    /// The number of non_zero entries in the B matrix.
    pub b_num_non_zero: usize,
    /// The number of non_zero entries in the C matrix.
    pub c_num_non_zero: usize,
    /// The A matrix in sparse representation.
    pub a: Matrix<F>,
    /// The B matrix in sparse representation.
    pub b: Matrix<F>,
    /// The C matrix in sparse representation.
    pub c: Matrix<F>,
}

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

/// Returns the generator of the domain of size `2^pow` and the shift onto the coset, both as
/// snarkjs computes them. The coset shift is the generator of the domain of twice the size, i.e.
/// a square root of the domain generator.
///
/// The generator differs from the one `ark_poly::Radix2EvaluationDomain` would pick (the old
/// arkworks-based computation also broke for bls12-381); it is computed as in snarkjs (more
/// precisely, in ffjavascript/src/wasm_field1.js), see `roots_of_unity`.
///
/// # Panics
///
/// Panics if `pow` exceeds the two-adicity of `F`, since no such domain exists.
#[instrument(level = "debug", name = "root of unity", skip_all)]
pub fn groth16_roots_of_unity<F: PrimeField + FftField>(pow: usize) -> (F, F) {
    assert!(
        pow <= F::TWO_ADICITY as usize,
        "no domain of size 2^{pow}: the two-adicity of the field is {}",
        F::TWO_ADICITY
    );
    let (q, roots) = roots_of_unity::<F>();
    let group_gen = roots[pow];
    let coset_shift = if F::TWO_ADICITY as usize == pow {
        q.square()
    } else {
        roots[pow + 1]
    };
    (group_gen, coset_shift)
}

/// A Groth16 proof protocol.
///
/// This struct should never be initialized, it only provides associated functions [`Groth16::prove`] and [`Groth16::verify`].
pub struct Groth16<P: Pairing> {
    phantom_data: PhantomData<P>,
}

// The MSM only exists for short-Weierstrass curves, and generic pairing groups offer no way to
// construct affine points from raw coordinates, so the prover names the curve configs behind
// `P::G1`/`P::G2` explicitly. `C1` and `C2` are inferred at every concrete call site.
impl<P, C1, C2> Groth16<P>
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
        initial: Projective<C>,
        query: &[Affine<C>],
        vk_param: Affine<C>,
        witness: &[P::ScalarField],
    ) -> Projective<C>
    where
        C: SWCurveConfig<ScalarField = P::ScalarField>,
    {
        let acc = msm_unchecked(&query[1..], witness);
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
        // The MSM truncates to the shorter slice, which for a well-matched key/witness map pair
        // is at most off by one (arkworks' h_query has domain_size - 1 elements). A shorter `h`
        // means the reduction's domain disagrees with the proving key's and the proof would be
        // silently invalid.
        eyre::ensure!(
            h.len() + 1 >= pkey.h_query.len(),
            "h has {} coefficients but the proving key expects {}: domain size mismatch",
            h.len(),
            pkey.h_query.len()
        );
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
                let result = msm_unchecked(&pkey.l_query, &witness[num_inputs..]);
                msm_l_query.exit();
                result
            },
            || {
                let msm_h_query = tracing::debug_span!("msm h_query").entered();
                //perform the msm for h
                let result = msm_unchecked(&pkey.h_query, &h);
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
