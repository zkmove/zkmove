// Copyright (c) zkMove Authors

use halo2_proofs::arithmetic::FieldExt;
use move_binary_format::access::ModuleAccess;
use move_binary_format::binary_views::{BinaryIndexedView, FunctionView};
use move_binary_format::file_format::{
    Bytecode, CompiledScript, FunctionDefinitionIndex, SignatureToken,
};
use move_binary_format::CompiledModule;
use movelang::type_transition;

/// The arithmetic operation Add, Sub, Mul, Div, Mod can be applied to
/// different types of unsigned integers. The type information is discarded
/// after execution, and we need to record the type for use in the step chip.

// a struct to record the value type of arithmetic operations
#[derive(Clone, Debug, Copy)]
pub struct ArithOperation {
    pub module_index: u16,
    pub function_index: u16,
    pub pc: u16,
    pub num_of_bytes: usize, // number of bytes of operand
}

// convert ArithOperation into a vector of field values
impl<F: FieldExt> From<&ArithOperation> for Vec<F> {
    fn from(arith_op: &ArithOperation) -> Vec<F> {
        vec![
            F::from_u128(arith_op.module_index as u128),
            F::from_u128(arith_op.function_index as u128),
            F::from_u128(arith_op.pc as u128),
            F::from_u128(arith_op.num_of_bytes as u128),
        ]
    }
}

pub struct ArithOperations(pub Vec<ArithOperation>);

impl<'a> From<(Option<&'a CompiledScript>, &'a [CompiledModule])> for ArithOperations {
    fn from((script, deps): (Option<&'a CompiledScript>, &'a [CompiledModule])) -> Self {
        Self(generate(script, deps))
    }
}
/// TODO(improve): we may only generate arith info of what the script needs.
fn generate(script: Option<&CompiledScript>, deps: &[CompiledModule]) -> Vec<ArithOperation> {
    if let Some(script) = script {
        vec![(
            0,
            0,
            type_transition::generate(
                &BinaryIndexedView::Script(script),
                &FunctionView::script(script),
            )
            .expect("generate type transition"),
        )]
    } else {
        vec![]
    }
    .into_iter()
    .chain(deps.iter().enumerate().flat_map(|(module_index, m)| {
        m.function_defs()
            .iter()
            .enumerate()
            .filter_map(move |(fun_index, func)| {
                if let Some(code) = func.code.as_ref() {
                    let fh = m.function_handle_at(func.function);
                    let transitions = type_transition::generate(
                        &BinaryIndexedView::Module(m),
                        &FunctionView::function(
                            m,
                            FunctionDefinitionIndex(fun_index as u16),
                            code,
                            fh,
                        ),
                    )
                    .expect("generate type transition");
                    Some((module_index + 1, fun_index, transitions))
                } else {
                    None
                }
            })
    }))
    .flat_map(|(module_index, func_index, type_transitions)| {
        type_transitions
            .into_iter()
            .filter_map(move |(pc, transition)| {
                let num_of_bytes = match transition.instr {
                    Bytecode::Add
                    | Bytecode::Sub
                    | Bytecode::Mul
                    | Bytecode::Div
                    | Bytecode::Mod => {
                        // TODO: support more bytecodes
                        Some(get_bytes_num(transition.consume.first().unwrap()))
                    }
                    _ => None,
                };
                num_of_bytes.map(|n| ArithOperation {
                    module_index: module_index as u16,
                    function_index: func_index as u16,
                    pc,
                    num_of_bytes: n as usize,
                })
            })
    })
    .collect()
}

fn get_bytes_num(s: &SignatureToken) -> u8 {
    match s {
        SignatureToken::U8 => 1,
        SignatureToken::U16 => 2,
        SignatureToken::U32 => 4,
        SignatureToken::U64 => 8,
        SignatureToken::U128 => 16,
        SignatureToken::U256 => 32,
        _ => unreachable!(),
    }
}
