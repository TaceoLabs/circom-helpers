use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, VerifyingKey};
use groth16::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};

use crate::groth16::Zkey;

/// Wrapper type to serialize [`ConstraintMatrices`] and [`ProvingKey`]s as a combined type.
///
/// Provides `From` implementations to convert to a [`Zkey`] or the inner types.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkZkey<P: Pairing> {
    /// The [`ConstraintMatricesWrapper`] to be able to use `ark-serialize`.
    pub matrices: ConstraintMatricesWrapper<P::ScalarField>,
    /// The [`ProvingKey`]
    pub pk: ProvingKey<P>,
}

/// A helper to enable [`ConstraintMatrices`] to be able to be serialized using `ark-serialize`.
#[derive(Clone)]
pub struct ConstraintMatricesWrapper<F: PrimeField>(pub ConstraintMatrices<F>);

impl<P: Pairing> ArkZkey<P> {
    /// Consumes the wrapper type and returns the underlying `ConstraintMatrices` and `ProvingKey`.
    pub fn into_inner(self) -> (ConstraintMatrices<P::ScalarField>, ProvingKey<P>) {
        self.into()
    }

    /// Gets references to the underlying `ConstraintMatrices` and `ProvingKey`.
    pub fn as_inner(&self) -> (&ConstraintMatrices<P::ScalarField>, &ProvingKey<P>) {
        (&self.matrices.0, &self.pk)
    }
}

impl<F: PrimeField> ConstraintMatricesWrapper<F> {
    /// Consumes the wrapper type and returns the underlying `ConstraintMatrices`.
    pub fn into_inner(self) -> ConstraintMatrices<F> {
        self.into()
    }
}

impl<F: PrimeField> CanonicalSerialize for ConstraintMatricesWrapper<F> {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.0.a.serialize_with_mode(&mut writer, compress)?;
        self.0.b.serialize_with_mode(&mut writer, compress)?;
        self.0.c.serialize_with_mode(&mut writer, compress)?;
        self.0
            .a_num_non_zero
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .b_num_non_zero
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .c_num_non_zero
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .num_instance_variables
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .num_witness_variables
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .num_constraints
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.0.a.serialized_size(compress)
            + self.0.b.serialized_size(compress)
            + self.0.c.serialized_size(compress)
            + self.0.a_num_non_zero.serialized_size(compress)
            + self.0.b_num_non_zero.serialized_size(compress)
            + self.0.c_num_non_zero.serialized_size(compress)
            + self.0.num_instance_variables.serialized_size(compress)
            + self.0.num_witness_variables.serialized_size(compress)
            + self.0.num_constraints.serialized_size(compress)
    }
}

impl<F: PrimeField> Valid for ConstraintMatricesWrapper<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.0.a.check()?;
        self.0.b.check()?;
        self.0.c.check()?;
        self.0.a_num_non_zero.check()?;
        self.0.b_num_non_zero.check()?;
        self.0.c_num_non_zero.check()?;
        self.0.num_instance_variables.check()?;
        self.0.num_witness_variables.check()?;
        self.0.num_constraints.check()?;
        Ok(())
    }
}

impl<F: PrimeField> CanonicalDeserialize for ConstraintMatricesWrapper<F> {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let a = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let b = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let a_num_non_zero =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let b_num_non_zero =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c_num_non_zero =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_instance_variables =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_witness_variables =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let num_constraints =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(ConstraintMatricesWrapper(ConstraintMatrices {
            a,
            b,
            c,
            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        }))
    }
}

impl<F: PrimeField> From<ConstraintMatrices<F>> for ConstraintMatricesWrapper<F> {
    fn from(value: ConstraintMatrices<F>) -> Self {
        Self(value)
    }
}

impl<F: PrimeField> From<ConstraintMatricesWrapper<F>> for ConstraintMatrices<F> {
    fn from(value: ConstraintMatricesWrapper<F>) -> Self {
        value.0
    }
}

impl<P: Pairing> From<ArkZkey<P>> for (ConstraintMatrices<P::ScalarField>, ProvingKey<P>) {
    fn from(value: ArkZkey<P>) -> Self {
        (value.matrices.into(), value.pk)
    }
}

impl<P: Pairing> From<Zkey<P>> for (ConstraintMatrices<P::ScalarField>, ProvingKey<P>) {
    fn from(zkey: Zkey<P>) -> Self {
        (
            ConstraintMatrices {
                num_instance_variables: zkey.n_public + 1,
                num_witness_variables: zkey.a_query.len() - zkey.n_public - 1,
                num_constraints: zkey.num_constraints,
                a_num_non_zero: zkey.a_matrix.len(),
                b_num_non_zero: zkey.b_matrix.len(),
                c_num_non_zero: 0,
                a: zkey.a_matrix,
                b: zkey.b_matrix,
                c: vec![],
            },
            ProvingKey {
                vk: VerifyingKey {
                    alpha_g1: zkey.alpha_g1,
                    beta_g2: zkey.beta_g2,
                    gamma_g2: zkey.gamma_g2,
                    delta_g2: zkey.delta_g2,
                    gamma_abc_g1: zkey.ic,
                },
                beta_g1: zkey.beta_g1,
                delta_g1: zkey.delta_g1,
                a_query: zkey.a_query,
                b_g1_query: zkey.b_g1_query,
                b_g2_query: zkey.b_g2_query,
                h_query: zkey.h_query,
                l_query: zkey.l_query,
            },
        )
    }
}

impl<P: Pairing> From<Zkey<P>> for ArkZkey<P> {
    fn from(zkey: Zkey<P>) -> Self {
        let (matrices, pk) = (
            ConstraintMatrices {
                num_instance_variables: zkey.n_public + 1,
                num_witness_variables: zkey.a_query.len() - zkey.n_public - 1,
                num_constraints: zkey.num_constraints,
                a_num_non_zero: zkey.a_matrix.len(),
                b_num_non_zero: zkey.b_matrix.len(),
                c_num_non_zero: 0,
                a: zkey.a_matrix,
                b: zkey.b_matrix,
                c: vec![],
            },
            ProvingKey {
                vk: VerifyingKey {
                    alpha_g1: zkey.alpha_g1,
                    beta_g2: zkey.beta_g2,
                    gamma_g2: zkey.gamma_g2,
                    delta_g2: zkey.delta_g2,
                    gamma_abc_g1: zkey.ic,
                },
                beta_g1: zkey.beta_g1,
                delta_g1: zkey.delta_g1,
                a_query: zkey.a_query,
                b_g1_query: zkey.b_g1_query,
                b_g2_query: zkey.b_g2_query,
                h_query: zkey.h_query,
                l_query: zkey.l_query,
            },
        );
        Self {
            matrices: matrices.into(),
            pk,
        }
    }
}
