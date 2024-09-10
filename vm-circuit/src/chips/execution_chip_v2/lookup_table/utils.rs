use crate::chips::execution_chip_v2::lookup_table::constant_table::ConstantTableRow;
use crate::chips::execution_chip_v2::lookup_table::function_table::FunctionTableRow;
use crate::chips::execution_chip_v2::utils::to_field::{ToField, ToFields};
use crate::chips::execution_chip_v2::Opcode;
use aptos_move_witnesses::static_info::bytecode::BytecodeInfo;
use aptos_move_witnesses::static_info::function::FunctionInfo;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::{Column, Error, Fixed};
use move_binary_format::file_format::{Bytecode, SignatureToken};
use move_core_types::u256::U256;
use movelang::value::{
    NUM_OF_BYTES_U128, NUM_OF_BYTES_U16, NUM_OF_BYTES_U256, NUM_OF_BYTES_U32, NUM_OF_BYTES_U64,
    NUM_OF_BYTES_U8,
};
use types::Field;

pub(crate) fn assign_fixed_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    table_columns: Vec<Column<Fixed>>,
    values: &[Vec<F>],
    table_name: &str,
) -> Result<(), Error> {
    layouter.assign_region(
        || "assign fixed table".to_string(),
        |mut region| {
            for (column_idx, column) in table_columns.iter().enumerate() {
                region.assign_fixed(
                    || format!("{:?}[{}][0]", table_name, column_idx),
                    *column,
                    0,
                    || Value::known(F::ZERO),
                )?;
                for i in 0..values.len() {
                    region.assign_fixed(
                        || format!("{:?}[{}][{}]", table_name, column_idx, i + 1),
                        *column,
                        i + 1,
                        || Value::known(values[i][column_idx]),
                    )?;
                }
            }
            Ok(())
        },
    )?;
    Ok(())
}

impl<F: Field> ToFields<F> for FunctionTableRow {
    fn to_fields(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_handle_index as u128),
            F::from_u128(self.def_module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.num_arg as u128),
            if self.entry { F::ONE } else { F::ZERO },
        ]
    }
}

impl<F: Field> ToFields<F> for ConstantTableRow {
    fn to_fields(&self) -> Vec<F> {
        vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.constant_index as u128),
            self.sub_index.to_field(),
        ]
        .into_iter()
        .chain(self.value.to_fields())
        .chain(vec![F::from(self.header as u64)])
        .collect()
    }
}

impl<F: Field> ToFields<F> for BytecodeInfo {
    fn to_fields(&self) -> Vec<F> {
        let mut field_elements = vec![
            F::from_u128(self.module_index as u128),
            F::from_u128(self.function_index as u128),
            F::from_u128(self.pc as u128),
        ];

        let fes = bytecode_to_fe(&self.bytecode, &self.ty_out);
        field_elements.append(&mut fes.to_vec());
        field_elements
    }
}

/// TODO: merge this with witnessing
/// Convert opcode, operand1 and operand2 of given bytecode into field elements
fn bytecode_to_fe<F: Field>(bytecode: &Bytecode, ty_out: &[SignatureToken]) -> [F; 3] {
    let fe_opcode = F::from(Opcode::from(bytecode.clone()).index() as u64);
    match *bytecode {
        Bytecode::CastU8
        | Bytecode::CastU16
        | Bytecode::CastU32
        | Bytecode::CastU64
        | Bytecode::CastU128
        | Bytecode::CastU256
        | Bytecode::Pop
        | Bytecode::Ret
        | Bytecode::LdTrue
        | Bytecode::LdFalse
        | Bytecode::Eq
        | Bytecode::Neq
        | Bytecode::Le
        | Bytecode::Lt
        | Bytecode::Ge
        | Bytecode::Gt
        | Bytecode::BitAnd
        | Bytecode::BitOr
        | Bytecode::Xor
        | Bytecode::And
        | Bytecode::Or
        | Bytecode::Not
        | Bytecode::ReadRef
        | Bytecode::WriteRef
        | Bytecode::FreezeRef
        | Bytecode::Abort => [fe_opcode, F::ZERO, F::ZERO],
        Bytecode::Add
        | Bytecode::Mul
        | Bytecode::Sub
        | Bytecode::Div
        | Bytecode::Mod
        | Bytecode::Shl
        | Bytecode::Shr => [
            fe_opcode,
            F::from_u128(get_num_bytes(&ty_out[0]) as u128),
            F::ZERO,
        ],
        Bytecode::LdU8(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
        Bytecode::LdU16(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
        Bytecode::LdU32(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
        Bytecode::LdU64(v) => [fe_opcode, F::from_u128(v as u128), F::ZERO],
        Bytecode::LdU128(v) => [fe_opcode, F::from_u128(v), F::ZERO],
        Bytecode::LdU256(v) => {
            let (lo, hi) = convert_u256_to_fe_pair::<F>(v);
            [fe_opcode, lo, hi]
        }
        Bytecode::LdConst(v) => [fe_opcode, F::from_u128(v.0 as u128), F::ZERO],
        Bytecode::CopyLoc(local_index)
        | Bytecode::MoveLoc(local_index)
        | Bytecode::StLoc(local_index)
        | Bytecode::MutBorrowLoc(local_index)
        | Bytecode::ImmBorrowLoc(local_index) => [fe_opcode, F::from(local_index as u64), F::ZERO],
        Bytecode::Branch(code_offset)
        | Bytecode::BrTrue(code_offset)
        | Bytecode::BrFalse(code_offset) => [fe_opcode, F::from(code_offset as u64), F::ZERO],
        Bytecode::Call(func_handle_index) => {
            [fe_opcode, F::from(func_handle_index.0 as u64), F::ZERO]
        }
        Bytecode::CallGeneric(idx) => [fe_opcode, F::from(idx.0 as u64), F::ZERO],
        Bytecode::Pack(sd_idx)
        | Bytecode::Unpack(sd_idx)
        | Bytecode::MoveTo(sd_idx)
        | Bytecode::MoveFrom(sd_idx)
        | Bytecode::Exists(sd_idx)
        | Bytecode::ImmBorrowGlobal(sd_idx)
        | Bytecode::MutBorrowGlobal(sd_idx) => [fe_opcode, F::from(sd_idx.0 as u64), F::ZERO],
        Bytecode::PackGeneric(idx)
        | Bytecode::UnpackGeneric(idx)
        | Bytecode::MoveToGeneric(idx)
        | Bytecode::MoveFromGeneric(idx)
        | Bytecode::ExistsGeneric(idx)
        | Bytecode::ImmBorrowGlobalGeneric(idx)
        | Bytecode::MutBorrowGlobalGeneric(idx) => [fe_opcode, F::from(idx.0 as u64), F::ZERO],
        Bytecode::ImmBorrowField(fh_idx) | Bytecode::MutBorrowField(fh_idx) => {
            [fe_opcode, F::from(fh_idx.0 as u64), F::ZERO]
        }
        Bytecode::ImmBorrowFieldGeneric(idx) | Bytecode::MutBorrowFieldGeneric(idx) => {
            [fe_opcode, F::from(idx.0 as u64), F::ZERO]
        }
        Bytecode::VecImmBorrow(idx)
        | Bytecode::VecMutBorrow(idx)
        | Bytecode::VecLen(idx)
        | Bytecode::VecPopBack(idx)
        | Bytecode::VecPushBack(idx)
        | Bytecode::VecSwap(idx) => [fe_opcode, F::from(idx.0 as u64), F::ZERO],
        Bytecode::VecPack(idx, num) | Bytecode::VecUnpack(idx, num) => {
            [fe_opcode, F::from(idx.0 as u64), F::from(num)]
        }
        _ => unimplemented!("{:?}", bytecode),
    }
}

fn get_num_bytes(s: &SignatureToken) -> usize {
    match s {
        SignatureToken::U8 => NUM_OF_BYTES_U8,
        SignatureToken::U16 => NUM_OF_BYTES_U16,
        SignatureToken::U32 => NUM_OF_BYTES_U32,
        SignatureToken::U64 => NUM_OF_BYTES_U64,
        SignatureToken::U128 => NUM_OF_BYTES_U128,
        SignatureToken::U256 => NUM_OF_BYTES_U256,
        _ => unreachable!(),
    }
}

pub fn convert_u256_to_fe_pair<F: Field>(input: U256) -> (F, F) {
    let bytes = input.to_le_bytes();
    let mut repr = F::Repr::default();
    repr[..16].copy_from_slice(&bytes[..16]);
    let lo = F::from_repr(repr).unwrap();
    repr[..16].copy_from_slice(&bytes[16..]);
    let hi = F::from_repr(repr).unwrap();
    (lo, hi)
}
