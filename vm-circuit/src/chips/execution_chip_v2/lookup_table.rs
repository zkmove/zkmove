use crate::chips::execution_chip_v2::lookup_table::byecode_table::BytecodeLookupTable;
use crate::chips::execution_chip_v2::lookup_table::function_table::FunctionLookupTable;
use crate::chips::execution_chip_v2::lookup_table::ux_table::UXTable;
use gadgets::impl_expr;
use halo2_proofs::plonk::{ConstraintSystem, Expression};
use std::marker::PhantomData;
use strum_macros::EnumIter;
use types::Field;

pub(crate) mod byecode_table;
pub(crate) mod function_table;
pub(crate) mod utils;
pub(crate) mod ux_table;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
/// Each item represents the lookup table to query
pub enum Table {
    /// The range check table for u8
    U8,
    /// The range check table for u16
    U16,
    /// The rest of the fixed table. See [`FixedTableTag`]
    Fixed,
    /// Lookup for bytecode table
    Bytecode,
    /// Lookup for function
    Function,
}

#[derive(Clone, Debug)]
pub(crate) enum Lookup<F> {
    /// Lookup to fixed table, which contains several pre-built tables such as
    /// range tables or bitwise tables.
    Fixed {
        /// Tag to specify which table to lookup.
        tag: Expression<F>,
        /// Values that must satisfy the pre-built relationship.
        values: [Expression<F>; 3],
    },
    Function {
        module_index: Expression<F>,
        function_index: Expression<F>,
        /// Number of arguments
        num_arg: Expression<F>,
    },
    /// Conditional lookup enabled by the first element.
    Conditional(Expression<F>, Box<Lookup<F>>),
}

impl<F: Field> Lookup<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }

    pub(crate) fn table(&self) -> Table {
        match self {
            Self::Fixed { .. } => Table::Fixed,
            Self::Function { .. } => Table::Function,
            Self::Conditional(_, lookup) => lookup.table(),
        }
    }

    pub(crate) fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::Fixed { tag, values } => [vec![tag.clone()], values.to_vec()].concat(),
            Self::Function {
                module_index,
                function_index,
                num_arg,
            } => {
                vec![
                    module_index.clone(),
                    function_index.clone(),
                    num_arg.clone(),
                ]
            }
            Self::Conditional(condition, lookup) => lookup
                .input_exprs()
                .into_iter()
                .map(|expr| condition.clone() * expr)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
/// Tags for different fixed tables
pub enum FixedTableTag {
    /// x == 0
    Zero = 0,
    /// 0 <= x < 5
    Range5,
    /// 0 <= x < 16
    Range16,
    /// 0 <= x < 32
    Range32,
    /// 0 <= x < 64
    Range64,
    /// 0 <= x < 128
    Range128,
    /// 0 <= x < 256
    Range256,
    /// 0 <= x < 512
    Range512,
    /// 0 <= x < 1024
    Range1024,
    /// -128 <= x < 128
    SignByte,
    /// bitwise AND
    BitwiseAnd,
    /// bitwise OR
    BitwiseOr,
    /// bitwise XOR
    BitwiseXor,
    /// power of 2
    Pow2,
}
impl_expr!(FixedTableTag);

pub struct LookupTableConfigV2<F> {
    pub(crate) u8_table: UXTable<8>,
    pub(crate) u10_table: UXTable<10>,
    pub(crate) u16_table: UXTable<16>,
    pub(crate) bytecode_table: BytecodeLookupTable,
    pub(crate) function_table: FunctionLookupTable,
    pub(crate) phantom_data: PhantomData<F>,
}

impl<F: Field> LookupTableConfigV2<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let u8_table = UXTable::construct(meta);
        let u10_table = UXTable::construct(meta);
        let u16_table = UXTable::construct(meta);
        let bytecode_table = BytecodeLookupTable::construct(meta);
        let function_table = FunctionLookupTable::construct(meta);
        Self {
            u8_table,
            u10_table,
            u16_table,
            bytecode_table,
            function_table,
            phantom_data: PhantomData,
        }
    }
}
