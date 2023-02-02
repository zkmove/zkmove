// Copyright (c) zkMove Authors

use crate::chips::execution_chip::lookup_tables::arith_op_lookup_table::ArithOpLookup;
use crate::chips::execution_chip::lookup_tables::bitwise_lookup_table::BitwiseLookup;
use crate::chips::execution_chip::lookup_tables::bytecode_lookup_table::BytecodeLookup;
use crate::chips::execution_chip::lookup_tables::call_lookup_table::CallLookup;
use crate::chips::execution_chip::lookup_tables::pow2_fixed_table::Pow2Lookup;
use crate::chips::execution_chip::lookup_tables::rw_table::RWLookup;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;

pub mod arith_op_lookup_table;
pub mod bitwise_lookup_table;
pub mod bytecode_lookup_table;
pub mod call_lookup_table;
pub mod pow2_fixed_table;
pub mod rw_table;
pub mod utils;

pub struct LookupsWithCondition<F: FieldExt> {
    pub rw_lookups: Vec<(RWLookup<F>, /*condition*/ Expression<F>)>,
    pub bytecode_lookups: Vec<(BytecodeLookup<F>, /*condition*/ Expression<F>)>,
    pub call_lookups: Vec<(CallLookup<F>, /*condition*/ Expression<F>)>,
    pub arith_op_lookups: Vec<(ArithOpLookup<F>, /*condition*/ Expression<F>)>,
    pub bitwise_lookups: Vec<(BitwiseLookup<F>, /*condition*/ Expression<F>)>,
    pub pow2_lookups: Vec<(Pow2Lookup<F>, Expression<F>)>,
}

impl<F: FieldExt> LookupsWithCondition<F> {
    pub fn new() -> Self {
        Self {
            rw_lookups: Vec::new(),
            bytecode_lookups: Vec::new(),
            call_lookups: Vec::new(),
            arith_op_lookups: Vec::new(),
            bitwise_lookups: Vec::new(),
            pow2_lookups: Vec::new(),
        }
    }
}

impl<F: FieldExt> Default for LookupsWithCondition<F> {
    fn default() -> Self {
        Self::new()
    }
}
