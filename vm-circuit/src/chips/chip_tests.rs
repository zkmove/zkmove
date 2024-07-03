// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::circuit_v2::VmCircuit;
use crate::witness::exec_step::ExecStep;
use crate::witness::exec_step::{LocalContext, OpcodeContext, StackContext};
use crate::witness::{CircuitConfigV2, WitnessV2};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use movelang::value::Value;
use std::marker::PhantomData;

#[test]
fn test_execution_chip() -> VmResult<()> {
    logger::init_for_test();
    let mut script = empty_script();
    script.code.code = vec![
        MoveBytecode::LdU64(1u64),
        MoveBytecode::LdU64(2u64),
        MoveBytecode::Add,
        MoveBytecode::Pop,
        MoveBytecode::Ret,
    ];
    let bytecodes = (script, vec![]).into();

    // LdU64(1u64)
    let opcode_context = OpcodeContext {
        clk: 0,
        frame_index: 0,
        module_index: 0,
        function_index: 0,
        pc: 0,
        sp: 0,
        opcode: Opcode::LdU64,
        aux0: Some(Value::u64(1)),
        aux1: None,
        step_counter: 1,
    };
    let stack_context = StackContext {
        stack_pop_index: 0,
        stack_pop_sub_index: 0,
        stack_pop_value: None,
        stack_pop_value_header: false,
        stack_pop_version: 0,

        stack_push_index: 1,
        stack_push_sub_index: 0,
        stack_push_value: Some(Value::u64(1)),
        stack_push_value_header: false,
        stack_push_version: 0,
    };
    let step_0 = ExecStep::new(opcode_context, stack_context, LocalContext::default());

    // LdU64(2u64)
    let opcode_context = OpcodeContext {
        clk: 2,
        frame_index: 0,
        module_index: 0,
        function_index: 0,
        pc: 1,
        sp: 1,
        opcode: Opcode::LdU64,
        aux0: Some(Value::u64(2)),
        aux1: None,
        step_counter: 1,
    };
    let stack_context = StackContext {
        stack_pop_index: 0,
        stack_pop_sub_index: 0,
        stack_pop_value: None,
        stack_pop_value_header: false,
        stack_pop_version: 0,

        stack_push_index: 2,
        stack_push_sub_index: 0,
        stack_push_value: Some(Value::u64(2)),
        stack_push_value_header: false,
        stack_push_version: 2,
    };
    let step_1 = ExecStep::new(opcode_context, stack_context, LocalContext::default());

    // first row of Add
    let opcode_context = OpcodeContext {
        clk: 4,
        frame_index: 0,
        module_index: 0,
        function_index: 0,
        pc: 2,
        sp: 2,
        opcode: Opcode::Add,
        aux0: None,
        aux1: None,
        step_counter: 2,
    };
    let stack_context = StackContext {
        stack_pop_index: 2,
        stack_pop_sub_index: 0,
        stack_pop_value: Some(Value::u64(2)),
        stack_pop_value_header: false,
        stack_pop_version: 2,

        stack_push_index: 0,
        stack_push_sub_index: 0,
        stack_push_value: None,
        stack_push_value_header: false,
        stack_push_version: 0,
    };
    let step_2 = ExecStep::new(opcode_context, stack_context, LocalContext::default());

    // second row of Add
    let opcode_context = OpcodeContext {
        clk: 6,
        frame_index: 0,
        module_index: 0,
        function_index: 0,
        pc: 2,
        sp: 1,
        opcode: Opcode::Add,
        aux0: None,
        aux1: None,
        step_counter: 1,
    };
    let stack_context = StackContext {
        stack_pop_index: 1,
        stack_pop_sub_index: 0,
        stack_pop_value: Some(Value::u64(1)),
        stack_pop_value_header: false,
        stack_pop_version: 0,

        stack_push_index: 1,
        stack_push_sub_index: 0,
        stack_push_value: Some(Value::u64(3)),
        stack_push_value_header: false,
        stack_push_version: 6,
    };
    let step_3 = ExecStep::new(opcode_context, stack_context, LocalContext::default());

    // Pop
    let opcode_context = OpcodeContext {
        clk: 8,
        frame_index: 0,
        module_index: 0,
        function_index: 0,
        pc: 3,
        sp: 1,
        opcode: Opcode::Pop,
        aux0: None,
        aux1: None,
        step_counter: 1,
    };
    let stack_context = StackContext {
        stack_pop_index: 1,
        stack_pop_sub_index: 0,
        stack_pop_value: Some(Value::u64(3)),
        stack_pop_value_header: false,
        stack_pop_version: 6,

        stack_push_index: 0,
        stack_push_sub_index: 0,
        stack_push_value: None,
        stack_push_value_header: false,
        stack_push_version: 0,
    };
    let step_4 = ExecStep::new(opcode_context, stack_context, LocalContext::default());

    // Ret
    let opcode_context = OpcodeContext {
        clk: 10,
        frame_index: 0,
        module_index: 0,
        function_index: 0,
        pc: 4,
        sp: 0,
        opcode: Opcode::Ret,
        aux0: None,
        aux1: None,
        step_counter: 1,
    };

    let step_5 = ExecStep::new(
        opcode_context,
        StackContext::default(),
        LocalContext::default(),
    );

    let exec_steps = vec![step_0, step_1, step_2, step_3, step_4, step_5];

    // FIXME
    let witness = WitnessV2::new(vec![], exec_steps, bytecodes, CircuitConfigV2::default());
    let vm_circuit = VmCircuit {
        witness,
        public_input: None,
        _maker: PhantomData,
    };
    let k = 10;
    let prover = MockProver::<Fr>::run(k, &vm_circuit, vec![vec![Fr::zero()]]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_ne!(prover.verify(), Ok(()));

    Ok(())
}
