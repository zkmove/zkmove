use crate::execution_circuit::step::NUM_OF_VALUE_LIMBS;
use crate::lookup_table::bitwise_table::BitwiseLookupTable;
use crate::lookup_table::byecode_table::BytecodeLookupTable;
use crate::lookup_table::constant_table::ConstantLookupTable;
use crate::lookup_table::fix_table::FixedTable;
use crate::lookup_table::function_table::FunctionLookupTable;
use crate::lookup_table::poseidon_table::PoseidonTable;
use crate::lookup_table::pow2::Pow2LookupTable;
use crate::lookup_table::ux_table::UXTable;
use field_exts::impl_expr;
use field_exts::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{
    Advice, Any, Column, ConstraintSystem, ErrorFront as Error, Expression, VirtualCells,
};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
use strum_macros::EnumIter;
use witness::static_info::StaticInfo;

use crate::execution_circuit::ExecutionCircuitConfigArgs;
pub(crate) use table_type::Table;

pub(crate) mod bitwise_table;
pub(crate) mod byecode_table;
pub(crate) mod constant_table;
pub(crate) mod fix_table;
pub(crate) mod function_table;
pub(crate) mod poseidon_table;
pub(crate) mod pow2;
pub(crate) mod utils;
pub(crate) mod ux_table;

/// Trait used to define lookup tables
pub trait LookupTable<F: Field> {
    /// Returns the list of ALL the table columns following the table order.
    fn columns(&self) -> Vec<Column<Any>>;

    /// Returns the list of ALL the table advice columns following the table
    /// order.
    fn advice_columns(&self) -> Vec<Column<Advice>> {
        self.columns()
            .iter()
            .map(|&col| col.try_into())
            .filter_map(|res| res.ok())
            .collect()
    }

    /// Returns the String annotations associated to each column of the table.
    fn annotations(&self) -> Vec<String>;

    /// Return the list of expressions used to define the lookup table.
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
    }

    /// Annotates a lookup table by passing annotations for each of it's
    /// columns.
    fn annotate_columns(&self, cs: &mut ConstraintSystem<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| cs.annotate_lookup_any_column(col, || ann))
    }

    /// Annotates columns of a table embedded within a circuit region.
    fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| region.name_column(|| ann, col))
    }
}

impl<F: Field, C: Into<Column<Any>> + Copy, const W: usize> LookupTable<F> for [C; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_any(*column, Rotation::cur()))
            .collect()
    }

    fn columns(&self) -> Vec<Column<Any>> {
        self.iter().map(|&col| col.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![]
    }
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
    PoseidonHash {
        /// The hash id of the poseidon hash
        hash_id: Expression<F>,
        /// The first input to the poseidon hash
        input0: Expression<F>,
        /// The second input to the poseidon hash
        input1: Expression<F>,
        /// The domain specification for the poseidon hash
        domain_spec: Expression<F>,
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
            Self::PoseidonHash { .. } => Table::PoseidonHash,
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
            Self::PoseidonHash {
                hash_id,
                input0,
                input1,
                domain_spec,
            } => vec![
                Expression::Constant(F::one()), // q_enable
                hash_id.clone(),
                input0.clone(),
                input1.clone(),
                Expression::Constant(F::zero()), // control
                domain_spec.clone(),
                Expression::Constant(F::one()), // heading mark
            ],

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
    /// 0 <= x < 1024
    Range1024,
}
impl_expr!(FixedTableTag);
impl FixedTableTag {
    /// build up the fixed table row values
    pub(crate) fn build<F: Field>(&self) -> Box<dyn Iterator<Item = [F; 4]>> {
        let tag = F::from(*self as u64);
        match self {
            Self::Zero => Box::new((0..1).map(move |_| [tag, F::zero(), F::zero(), F::zero()])),
            Self::Range16 => {
                Box::new((0..16).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range32 => {
                Box::new((0..32).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range64 => {
                Box::new((0..64).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range128 => {
                Box::new((0..128).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range256 => {
                Box::new((0..256).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range1024 => {
                Box::new((0..1024).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
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
    pub(crate) poseidon_table: Option<PoseidonTable>,
    pub(crate) phantom_data: PhantomData<F>,
}

impl<F: Field> LookupTableConfigV2<F> {
    pub fn new(meta: &mut ConstraintSystem<F>, config_args: &ExecutionCircuitConfigArgs) -> Self {
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
        let poseidon_table = if config_args.use_poseidon_hash {
            Some(PoseidonTable::construct(meta))
        } else {
            None
        };
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
            poseidon_table,
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

    pub fn tables_height(
        &self,
        static_info: &StaticInfo,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> usize {
        // Collect the heights of all tables
        let heights = vec![
            fixed_table_tags
                .iter()
                .flat_map(|tag| tag.build::<F>())
                .count(),
            self.nibble_table.build::<F>().count(),
            self.u8_table.build::<F>().count(),
            self.u10_table.build::<F>().count(),
            #[cfg(feature = "table-u16")]
            self.u16_table.build::<F>().count(),
            self.bytecode_table.build::<F>(static_info).len(),
            self.constant_table.build::<F>(static_info).len(),
            self.function_table.build::<F>(static_info).len(),
            self.bitwise_table.build::<F>().count(),
            self.pow2_table.build::<F>().len(),
        ];

        // Return the maximum height
        heights.into_iter().max().unwrap_or(0)
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
            Table::PoseidonHash => self
                .poseidon_table
                .expect("Poseidon table is not enabled in the config")
                .table_exprs(meta),
        }
    }
}
