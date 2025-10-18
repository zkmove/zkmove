use crate::utils::cached_region::CachedRegion;
use crate::utils::cell_manager::{Cell, CellType};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{ErrorFront as Error, Expression};
use std::hash::{Hash, Hasher};
use types::Field;

pub(crate) mod base_constraint_builder;
pub(crate) mod constraint_builder_v2;
#[derive(Debug, Clone)]
pub struct StoredExpression<F> {
    pub(crate) name: String,
    pub(crate) cell: Cell<F>,
    pub(crate) cell_type: CellType,
    pub(crate) expr: Expression<F>,
    pub(crate) expr_id: String,
}

impl<F> Hash for StoredExpression<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expr_id.hash(state);
        self.cell_type.hash(state);
    }
}

/// Evaluate an expression using a `CachedRegion` at `offset`.
pub(crate) fn evaluate_expression<F: Field>(
    expr: &Expression<F>,
    region: &CachedRegion<'_, '_, F>,
    offset: usize,
) -> Value<F> {
    expr.evaluate(
        &|scalar| Value::known(scalar),
        &|_| unimplemented!("selector column"),
        &|fixed_query| {
            Value::known(region.get_fixed(
                offset,
                fixed_query.column_index(),
                fixed_query.rotation(),
            ))
        },
        &|advice_query| {
            Value::known(region.get_advice(
                offset,
                advice_query.column_index(),
                advice_query.rotation(),
            ))
        },
        &|_| unimplemented!("instance column"),
        &|challenge| *region.challenges().indexed()[challenge.index()],
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, scalar| a * Value::known(scalar),
    )
}

impl<F: Field> StoredExpression<F> {
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
    ) -> Result<Value<F>, Error> {
        let value = evaluate_expression(&self.expr, region, offset);
        self.cell.assign(region, offset, value)?;
        Ok(value)
    }

    pub fn assign_empty(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
    ) -> Result<(), Error> {
        self.cell.assign(region, offset, Value::known(F::ZERO))?;
        Ok(())
    }
}

/// Decodes a field element from its byte representation in little endian order
pub(crate) mod from_bytes {
    use gadgets::util::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;
    /// Maximum number of bytes that an integer can fit in field without wrapping
    /// around.
    pub(crate) const MAX_N_BYTES_INTEGER: usize = 31;

    pub(crate) fn expr<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub(crate) fn value<F: Field>(bytes: &[u8]) -> F {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

/// Decodes a field element from its 4, 8 or 16 bits limbs representation in little endian order
pub(crate) mod from_limbs {
    use gadgets::util::Expr;
    use halo2_proofs::plonk::Expression;
    use types::Field;

    pub(crate) fn expr<F: Field, E: Expr<F>, const LIMB_BITS: usize>(limbs: &[E]) -> Expression<F> {
        debug_assert!(
            limbs.len() <= 255 / LIMB_BITS,
            "Too many limbs to compose an integer in field"
        );
        debug_assert!(
            LIMB_BITS == 4 || LIMB_BITS == 8 || LIMB_BITS == 16,
            "Only 4-bits, 8-bits or 16-bits limbs supported"
        );
        let mut value = 0.expr();
        let mut multiplier = F::ONE;
        for limb in limbs.iter() {
            value = value + limb.expr() * multiplier;
            multiplier *= F::from(1u64 << LIMB_BITS);
        }
        value
    }

    pub(crate) fn value<F: Field, const LIMB_BITS: usize>(limbs: &[u64]) -> F {
        debug_assert!(
            limbs.len() <= 255 / LIMB_BITS,
            "Too many limbs to compose an integer in field"
        );
        debug_assert!(
            LIMB_BITS == 4 || LIMB_BITS == 8 || LIMB_BITS == 16,
            "Only 4-bits, 8-bits or 16-bits limbs supported"
        );
        let mut value = F::ZERO;
        let mut multiplier = F::ONE;
        for limb in limbs.iter() {
            value += F::from(*limb) * multiplier;
            multiplier *= F::from(1u64 << LIMB_BITS);
        }
        value
    }
}

/// Transposes an `Value` of a [`Result`] into a [`Result`] of an `Value`.
pub(crate) fn transpose_val_ret<F, E>(value: Value<Result<F, E>>) -> Result<Value<F>, E> {
    let mut ret = Ok(Value::unknown());
    value.map(|value| {
        ret = value.map(Value::known);
    });
    ret
}

pub(crate) mod to_field {
    use crate::execution_circuit::utils::{from_limbs, pow_of_two};
    use move_vm_runtime::witnessing::traced_value::ValueItem;
    use types::Field;
    use witnesses::value_repr::sub_index::{SubIndex, N_BITS_ONE_LIMB};
    use witnesses::value_repr::word::Word;

    pub(crate) trait ToFields<F: Field> {
        fn to_fields(&self) -> Vec<F>;
    }
    pub(crate) trait ToField<F: Field> {
        fn to_field(&self) -> F;
    }

    impl<F: Field> ToField<F> for SubIndex {
        fn to_field(&self) -> F {
            from_limbs::value::<F, N_BITS_ONE_LIMB>(
                &self.to_vec().iter().map(|v| *v as u64).collect::<Vec<_>>(),
            )
        }
    }

    impl<F: Field> ToFields<F> for Word {
        fn to_fields(&self) -> Vec<F> {
            self.inner().iter().map(|&x| F::from_u128(x)).collect()
        }
    }

    impl<F: Field> ToField<F> for bool {
        fn to_field(&self) -> F {
            if *self {
                F::ONE
            } else {
                F::ZERO
            }
        }
    }

    impl<F: Field> ToFields<F> for ValueItem {
        fn to_fields(&self) -> Vec<F> {
            vec![
                SubIndex::new(self.sub_index.clone()).to_field(),
                self.header.to_field(),
            ]
            .into_iter()
            .chain(Word::from(&self.value).to_fields())
            .collect()
        }
    }
    impl<F: Field> ToField<F> for Word {
        fn to_field(&self) -> F {
            F::from_u128(self.hi()) * pow_of_two::<F>(128) + F::from_u128(self.lo())
        }
    }
}

/// Returns 2**by as Field
pub(crate) fn pow_of_two<F: Field>(by: usize) -> F {
    F::from(2).pow([by as u64, 0, 0, 0])
}

/// Returns 2**by as Expression
pub(crate) fn pow_of_two_expr<F: Field>(by: usize) -> Expression<F> {
    Expression::Constant(pow_of_two(by))
}
