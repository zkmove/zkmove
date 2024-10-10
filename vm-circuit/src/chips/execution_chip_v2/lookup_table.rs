use crate::chips::execution_chip_v2::lookup_table::bitwise_table::BitwiseLookupTable;
use crate::chips::execution_chip_v2::lookup_table::byecode_table::BytecodeLookupTable;
use crate::chips::execution_chip_v2::lookup_table::constant_table::ConstantLookupTable;
use crate::chips::execution_chip_v2::lookup_table::fix_table::FixedTable;
use crate::chips::execution_chip_v2::lookup_table::function_table::FunctionLookupTable;
use crate::chips::execution_chip_v2::lookup_table::pow2::Pow2LookupTable;
use crate::chips::execution_chip_v2::lookup_table::ux_table::UXTable;
use crate::chips::execution_chip_v2::step_v2::NUM_OF_VALUE_LIMBS;
use crate::table::LookupTable;
use aptos_move_witnesses::static_info::StaticInfo;
use gadgets::impl_expr;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, VirtualCells};
use std::marker::PhantomData;
use strum_macros::EnumIter;
use types::Field;

pub(crate) mod bitwise_table;
pub(crate) mod byecode_table;
pub(crate) mod constant_table;
pub(crate) mod fix_table;
pub(crate) mod function_table;
pub(crate) mod pow2;
pub(crate) mod utils;
pub(crate) mod ux_table;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
/// Each item represents the lookup table to query
pub enum Table {
    /// The range check table for 4-bits
    Nibble,
    /// The range check table for u8
    U8,
    /// The range check table for u10
    U10,
    /// The range check table for u16
    #[cfg(feature = "table-u16")]
    U16,
    /// The rest of the fixed table. See [`FixedTableTag`]
    Fixed,
    /// Lookup for bytecode table
    Bytecode,
    /// Lookup for constant table
    Constant,
    /// Lookup for function
    Function,
    /// Pow of 2
    Pow2,
    /// Bitwise lookup
    Bitwise,
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
        function_handle_index: Expression<F>,
        def_module_index: Expression<F>,
        function_index: Expression<F>,
        num_arg: Expression<F>,
        entry: Expression<F>,
    },
    Pow2 {
        value: Expression<F>,
        pow_lo: Expression<F>,
        pow_hi: Expression<F>,
    },
    Constant {
        module_index: Expression<F>,
        constant_index: Expression<F>,
        sub_index: Expression<F>,
        value: [Expression<F>; NUM_OF_VALUE_LIMBS],
        header: Expression<F>,
    },
    Bitwise {
        opcode: Expression<F>,
        value_1: Expression<F>,
        value_2: Expression<F>,
        result: Expression<F>,
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
            Self::Bitwise { .. } => Table::Bitwise,
            Self::Constant { .. } => Table::Constant,
            Self::Pow2 { .. } => Table::Pow2,
            Self::Conditional(_, lookup) => lookup.table(),
        }
    }

    pub(crate) fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::Fixed { tag, values } => [vec![tag.clone()], values.to_vec()].concat(),
            Self::Function {
                module_index,
                function_handle_index,
                def_module_index,
                function_index,
                num_arg,
                entry,
            } => {
                vec![
                    module_index.clone(),
                    function_handle_index.clone(),
                    def_module_index.clone(),
                    function_index.clone(),
                    num_arg.clone(),
                    entry.clone(),
                ]
            }
            Self::Constant {
                module_index,
                constant_index,
                sub_index,
                value,
                header,
            } => vec![module_index, constant_index, sub_index]
                .into_iter()
                .chain(value)
                .chain(vec![header])
                .cloned()
                .collect(),
            Self::Bitwise {
                opcode,
                value_1,
                value_2,
                result,
            } => {
                vec![
                    opcode.clone(),
                    value_1.clone(),
                    value_2.clone(),
                    result.clone(),
                ]
            }
            Self::Pow2 {
                value,
                pow_lo,
                pow_hi,
            } => {
                vec![value.clone(), pow_lo.clone(), pow_hi.clone()]
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
impl FixedTableTag {
    /// build up the fixed table row values
    pub(crate) fn build<F: Field>(&self) -> Box<dyn Iterator<Item = [F; 4]>> {
        let tag = F::from(*self as u64);
        match self {
            Self::Zero => Box::new((0..1).map(move |_| [tag, F::ZERO, F::ZERO, F::ZERO])),
            Self::Range5 => {
                Box::new((0..5).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range16 => {
                Box::new((0..16).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range32 => {
                Box::new((0..32).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range64 => {
                Box::new((0..64).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range128 => {
                Box::new((0..128).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range256 => {
                Box::new((0..256).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range512 => {
                Box::new((0..512).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range1024 => {
                Box::new((0..1024).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::SignByte => Box::new((0..256).map(move |value| {
                [
                    tag,
                    F::from(value),
                    F::from((value >> 7) * 0xFFu64),
                    F::ZERO,
                ]
            })),
            Self::BitwiseAnd => Box::new((0..16).flat_map(move |lhs| {
                (0..16).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs & rhs)])
            })),
            Self::BitwiseOr => Box::new((0..16).flat_map(move |lhs| {
                (0..16).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs | rhs)])
            })),
            Self::BitwiseXor => Box::new((0..16).flat_map(move |lhs| {
                (0..16).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs ^ rhs)])
            })),
            Self::Pow2 => Box::new((0..256).map(move |value| {
                let (pow_lo, pow_hi) = if value < 128 {
                    (F::from_u128(1_u128 << value), F::from(0))
                } else {
                    (F::from(0), F::from_u128(1 << (value - 128)))
                };
                [tag, F::from(value), pow_lo, pow_hi]
            })),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LookupTableConfigV2<F> {
    pub(crate) fixed_table: FixedTable,
    pub(crate) nibble_table: UXTable<4>,
    pub(crate) u8_table: UXTable<8>,
    pub(crate) u10_table: UXTable<10>,
    #[cfg(feature = "table-u16")]
    pub(crate) u16_table: UXTable<16>,
    pub(crate) bytecode_table: BytecodeLookupTable,
    pub(crate) constant_table: ConstantLookupTable,
    pub(crate) function_table: FunctionLookupTable,
    pub(crate) bitwise_table: BitwiseLookupTable,
    pub(crate) pow2_table: Pow2LookupTable,
    pub(crate) phantom_data: PhantomData<F>,
}

impl<F: Field> LookupTableConfigV2<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let fixed_table = FixedTable::construct(meta);
        let nibble_table = UXTable::construct(meta);
        let u8_table = UXTable::construct(meta);
        let u10_table = UXTable::construct(meta);
        #[cfg(feature = "table-u16")]
        let u16_table = UXTable::construct(meta);
        let bytecode_table = BytecodeLookupTable::construct(meta);
        let constant_table = ConstantLookupTable::construct(meta);
        let function_table = FunctionLookupTable::construct(meta);
        let bitwise_table = BitwiseLookupTable::construct(meta);
        let pow2_table = Pow2LookupTable::construct(meta);
        Self {
            fixed_table,
            nibble_table,
            u8_table,
            u10_table,
            #[cfg(feature = "table-u16")]
            u16_table,
            bytecode_table,
            constant_table,
            function_table,
            bitwise_table,
            pow2_table,
            phantom_data: PhantomData,
        }
    }

    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        fixed_table_tags: Vec<FixedTableTag>,
        static_info: &StaticInfo,
    ) -> Result<(), Error> {
        self.fixed_table.load(layouter, fixed_table_tags)?;
        self.nibble_table.load(layouter)?;
        self.u8_table.load(layouter)?;
        self.u10_table.load(layouter)?;
        #[cfg(feature = "table-u16")]
        self.u16_table.load(layouter)?;
        self.bytecode_table.load(layouter, static_info)?;
        self.constant_table.load(layouter, static_info)?;
        self.function_table.load(layouter, static_info)?;
        self.bitwise_table.load(layouter)?;
        self.pow2_table.load(layouter)?;
        Ok(())
    }

    pub fn table_exprs(&self, table: Table, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        match table {
            Table::Fixed => self.fixed_table.table_exprs(meta),
            Table::Nibble => self.nibble_table.table_exprs(meta),
            Table::U8 => self.u8_table.table_exprs(meta),
            Table::U10 => self.u10_table.table_exprs(meta),
            #[cfg(feature = "table-u16")]
            Table::U16 => self.u16_table.table_exprs(meta),
            Table::Function => self.function_table.table_exprs(meta),
            Table::Bitwise => self.bitwise_table.table_exprs(meta),
            Table::Bytecode => self.bytecode_table.table_exprs(meta),
            Table::Constant => self.constant_table.table_exprs(meta),
            Table::Pow2 => self.pow2_table.table_exprs(meta),
        }
    }
}
