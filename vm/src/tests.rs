// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use crate::state::StateStore;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use move_binary_format::CompiledModule;
use movelang::generic_call_graph::generate_for_script;
use movelang::value::{SimpleValue, Value};
use movelang::value_ext::ValueHeader;
use vm_circuit::chips::execution_chip::opcode::Opcode;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::find_best_k;
use vm_circuit::witness::arith_operations::ArithOperations;
use vm_circuit::witness::execution_steps::ExecutionStep;
use vm_circuit::witness::rw_operations::RW::{READ, WRITE};
use vm_circuit::witness::rw_operations::{LocalsOp, RWOperation, StackOp};
use vm_circuit::witness::{CircuitConfig, Witness};

#[test]
fn test_execution_step() -> VmResult<()> {
    logger::init_for_test();
    let mut script = empty_script();
    script.code.code = vec![
        MoveBytecode::LdU64(1u64),
        MoveBytecode::LdU64(2u64),
        MoveBytecode::Add,
        MoveBytecode::Pop,
        MoveBytecode::Ret,
    ];
    let bytecodes = (script.clone(), vec![]).into();
    let deps: &[CompiledModule] = &[];
    let arith_operations = ArithOperations::from((Some(&script), deps)).0;
    let mut blob = vec![];
    script.serialize(&mut blob).expect("script must serialize");

    let runtime = Runtime::<Fr>::new();
    let mut data_store = StateStore::new();
    let mut interp = Interpreter::<Fr>::new();
    let generic_graph = generate_for_script(&script, &data_store);

    let (entry, ty_arguments) = runtime
        .loader()
        .load_script(&blob, &[], &data_store)
        .map_err(|e| {
            error!("load script failed: {:?}", e);
            RuntimeError::new(StatusCode::ScriptLoadingError)
        })
        .unwrap();
    let arg_types = entry.parameter_types().to_vec();
    let mut exec_steps = Vec::new();
    let mut rw_operations = Vec::new();
    let mut generic_type_infos = Vec::new();
    interp
        .execute_function(
            entry,
            ty_arguments,
            None,
            None,
            arg_types,
            runtime.loader(),
            &mut data_store,
            runtime.get_natives(),
            runtime.get_native_context_exts(),
            &mut exec_steps,
            &mut rw_operations,
            &mut generic_type_infos,
            &generic_graph,
        )
        .unwrap();

    let expected_step_0 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 0,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_1 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        frame_index: 0,
        locals_index: 0,
        gc: 3,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_2 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        frame_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: Some(Value::u8(8u8)),
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_3 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        frame_index: 0,
        locals_index: 0,
        gc: 15,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: Some(Value::u64(3u64)),
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_4 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: Some(Value::u64(0)),
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_5 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };

    assert_eq!(exec_steps[0], expected_step_0, "result is not expected");
    assert_eq!(exec_steps[1], expected_step_1, "result is not expected");
    assert_eq!(exec_steps[2], expected_step_2, "result is not expected");
    assert_eq!(exec_steps[3], expected_step_3, "result is not expected");
    assert_eq!(exec_steps[4], expected_step_4, "result is not expected");
    assert_eq!(exec_steps[5], expected_step_5, "result is not expected");

    let expected_rw_op_0 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let expected_rw_op_1 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(1)),

        rw: WRITE,
        gc: 1,
    });
    let expected_rw_op_2 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 2,
    });
    let expected_rw_op_3 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 3,
    });
    let expected_rw_op_4 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 1,
        value: Some(SimpleValue::u64(2)),

        rw: WRITE,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 5,
    });
    let expected_rw_op_6 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let expected_rw_op_7 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 1,
        value: Some(SimpleValue::u64(2)),

        rw: READ,
        gc: 7,
    });
    let expected_rw_op_8 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 8,
    });
    let expected_rw_op_9 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 9,
    });
    let expected_rw_op_10 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(1)),

        rw: READ,
        gc: 10,
    });
    let expected_rw_op_11 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 11,
    });
    let expected_rw_op_12 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 12,
    });
    let expected_rw_op_13 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(3)),

        rw: WRITE,
        gc: 13,
    });
    let expected_rw_op_14 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 14,
    });
    let expected_rw_op_15 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 15,
    });
    let expected_rw_op_16 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(3)),

        rw: READ,
        gc: 16,
    });
    let expected_rw_op_17 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 17,
    });

    assert_eq!(rw_operations[0], expected_rw_op_0, "result is not expected");
    assert_eq!(rw_operations[1], expected_rw_op_1, "result is not expected");
    assert_eq!(rw_operations[2], expected_rw_op_2, "result is not expected");
    assert_eq!(rw_operations[3], expected_rw_op_3, "result is not expected");
    assert_eq!(rw_operations[4], expected_rw_op_4, "result is not expected");
    assert_eq!(rw_operations[5], expected_rw_op_5, "result is not expected");
    assert_eq!(rw_operations[6], expected_rw_op_6, "result is not expected");
    assert_eq!(rw_operations[7], expected_rw_op_7, "result is not expected");
    assert_eq!(rw_operations[8], expected_rw_op_8, "result is not expected");
    assert_eq!(rw_operations[9], expected_rw_op_9, "result is not expected");
    assert_eq!(
        rw_operations[10], expected_rw_op_10,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[11], expected_rw_op_11,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[12], expected_rw_op_12,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[13], expected_rw_op_13,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[14], expected_rw_op_14,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[15], expected_rw_op_15,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[16], expected_rw_op_16,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[17], expected_rw_op_17,
        "result is not expected"
    );

    let circuit_config = CircuitConfig::default();
    let witness = Witness::new(
        exec_steps,
        rw_operations,
        bytecodes,
        Default::default(),
        vec![],
        arith_operations,
        Default::default(),
        Default::default(),
        Default::default(),
        circuit_config,
    );
    let vm_circuit = VmCircuit {
        witness,
        public_input: None,
    };
    let k = 10;
    let prover = MockProver::<Fr>::run(k, &vm_circuit, vec![vec![Fr::zero()]]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}

#[test]
fn test_nop_step() -> VmResult<()> {
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

    let step_0 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 0,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_1 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        frame_index: 0,
        locals_index: 0,
        gc: 3,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_2 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        frame_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: Some(Value::u8(8u8)),
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_3 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        frame_index: 0,
        locals_index: 0,
        gc: 15,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: Some(Value::u64(3u64)),
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_4 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: Some(Value::u64(0)),
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_5 = ExecutionStep::<Fr> {
        context_id: 1,
        opcode: Opcode::Nop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_6 = ExecutionStep::<Fr> {
        context_id: 1,
        opcode: Opcode::Nop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_7 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };

    let exec_steps = vec![
        step_0, step_1, step_2, step_3, step_4, step_5, step_6, step_7,
    ];

    let rw_op_0 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let rw_op_1 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 1,
    });
    let rw_op_2 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u64(1)),

        rw: WRITE,
        gc: 2,
    });
    let rw_op_3 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 3,
    });
    let rw_op_4 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 1,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 4,
    });
    let rw_op_5 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 2,
        value: Some(SimpleValue::u64(2)),

        rw: WRITE,
        gc: 5,
    });
    let rw_op_6 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let rw_op_7 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 1,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 7,
    });
    let rw_op_8 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 2,
        value: Some(SimpleValue::u64(2)),

        rw: READ,
        gc: 8,
    });
    let rw_op_9 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 9,
    });
    let rw_op_10 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 10,
    });
    let rw_op_11 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u64(1)),

        rw: READ,
        gc: 11,
    });
    let rw_op_12 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 12,
    });
    let rw_op_13 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 13,
    });
    let rw_op_14 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u64(3)),

        rw: WRITE,
        gc: 14,
    });
    let rw_op_15 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 15,
    });
    let rw_op_16 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 16,
    });
    let rw_op_17 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u64(3)),

        rw: READ,
        gc: 17,
    });
    let fake_rw_op = RWOperation::<Fr>::LocalsOp(LocalsOp {
        frame_index: 0,
        index: 0,
        address_ext: 0,
        value: Some(SimpleValue::u64(3)),

        rw: WRITE,
        gc: 12,
    });

    let rw_operations = vec![
        rw_op_0, rw_op_1, rw_op_2, rw_op_3, rw_op_4, rw_op_5, rw_op_6, rw_op_7, rw_op_8, rw_op_9,
        rw_op_10, rw_op_11, rw_op_12, rw_op_13, rw_op_14, rw_op_15, rw_op_16, rw_op_17, fake_rw_op,
    ];

    let circuit_config = CircuitConfig::default();
    let witness = Witness::new(
        exec_steps,
        rw_operations,
        bytecodes,
        Default::default(),
        vec![],
        vec![],
        Default::default(),
        Default::default(),
        Default::default(),
        circuit_config,
    );
    let vm_circuit = VmCircuit {
        witness,
        public_input: None,
    };
    let k = 10;
    let prover = MockProver::<Fr>::run(k, &vm_circuit, vec![vec![Fr::zero()]]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_ne!(prover.verify(), Ok(()));

    Ok(())
}

#[test]
fn test_nop_steps() -> VmResult<()> {
    logger::init_for_test();
    let mut script = empty_script();
    script.code.code = vec![
        MoveBytecode::LdU64(1u64),
        MoveBytecode::LdU64(2u64),
        MoveBytecode::Add,
        MoveBytecode::Pop,
        MoveBytecode::Ret,
    ];

    let runtime = Runtime::<Fr>::new();
    let mut data_store = StateStore::new();
    let circuit_config = CircuitConfig::default().max_step_row(Some(100));
    let trace = runtime.execute_script(script.clone(), vec![], None, None, &mut data_store)?;
    let witness = runtime.process_execution_trace(
        vec![],
        Some(script),
        None,
        vec![],
        trace,
        circuit_config,
    )?;

    let vm_circuit = VmCircuit {
        witness,
        public_input: None,
    };
    let k = find_best_k(&vm_circuit);

    let expected_step_0 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 0,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_1 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        frame_index: 0,
        locals_index: 0,
        gc: 3,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_2 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        frame_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: Some(Value::u8(8u8)),
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_3 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        frame_index: 0,
        locals_index: 0,
        gc: 15,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: Some(Value::u64(3u64)),
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_4 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: Some(Value::u64(0)),
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let expected_step_5 = ExecutionStep {
        context_id: 1,
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 18,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };

    let steps = &vm_circuit.witness.exec_steps;
    assert_eq!(steps[0], expected_step_0, "result is not expected");
    assert_eq!(steps[1], expected_step_1, "result is not expected");
    assert_eq!(steps[2], expected_step_2, "result is not expected");
    assert_eq!(steps[3], expected_step_3, "result is not expected");
    assert_eq!(steps[4], expected_step_4, "result is not expected");
    assert_eq!(steps[5], expected_step_5, "result is not expected");

    let expected_rw_op_0 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let expected_rw_op_1 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(1)),

        rw: WRITE,
        gc: 1,
    });
    let expected_rw_op_2 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 2,
    });
    let expected_rw_op_3 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 3,
    });
    let expected_rw_op_4 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 1,
        value: Some(SimpleValue::u64(2)),

        rw: WRITE,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 5,
    });
    let expected_rw_op_6 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let expected_rw_op_7 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 1,
        value: Some(SimpleValue::u64(2)),

        rw: READ,
        gc: 7,
    });
    let expected_rw_op_8 = RWOperation::<Fr>::StackOp(StackOp {
        address: 1,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 8,
    });
    let expected_rw_op_9 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 9,
    });
    let expected_rw_op_10 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(1)),

        rw: READ,
        gc: 10,
    });
    let expected_rw_op_11 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 11,
    });
    let expected_rw_op_12 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 12,
    });
    let expected_rw_op_13 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(3)),

        rw: WRITE,
        gc: 13,
    });
    let expected_rw_op_14 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: WRITE,
        gc: 14,
    });
    let expected_rw_op_15 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 15,
    });
    let expected_rw_op_16 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 1,
        value: Some(SimpleValue::u64(3)),

        rw: READ,
        gc: 16,
    });
    let expected_rw_op_17 = RWOperation::<Fr>::StackOp(StackOp {
        address: 0,
        address_ext: 2,
        value: Some(SimpleValue::u128(0)),

        rw: READ,
        gc: 17,
    });

    let rw_operations = &vm_circuit.witness.rw_operations.0;

    assert_eq!(rw_operations[0], expected_rw_op_0, "result is not expected");
    assert_eq!(rw_operations[1], expected_rw_op_1, "result is not expected");
    assert_eq!(rw_operations[2], expected_rw_op_2, "result is not expected");
    assert_eq!(rw_operations[3], expected_rw_op_3, "result is not expected");
    assert_eq!(rw_operations[4], expected_rw_op_4, "result is not expected");
    assert_eq!(rw_operations[5], expected_rw_op_5, "result is not expected");
    assert_eq!(rw_operations[6], expected_rw_op_6, "result is not expected");
    assert_eq!(rw_operations[7], expected_rw_op_7, "result is not expected");
    assert_eq!(rw_operations[8], expected_rw_op_8, "result is not expected");
    assert_eq!(rw_operations[9], expected_rw_op_9, "result is not expected");
    assert_eq!(
        rw_operations[10], expected_rw_op_10,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[11], expected_rw_op_11,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[12], expected_rw_op_12,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[13], expected_rw_op_13,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[14], expected_rw_op_14,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[15], expected_rw_op_15,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[16], expected_rw_op_16,
        "result is not expected"
    );
    assert_eq!(
        rw_operations[17], expected_rw_op_17,
        "result is not expected"
    );

    let prover = MockProver::<Fr>::run(k, &vm_circuit, vec![vec![Fr::zero()]]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}

#[test]
fn test_empty_ops() -> VmResult<()> {
    logger::init_for_test();
    let mut script = empty_script();
    script.code.code = vec![
        MoveBytecode::LdU64(1u64),
        MoveBytecode::LdU64(2u64),
        MoveBytecode::Add,
        MoveBytecode::Pop,
        MoveBytecode::Ret,
    ];

    let runtime = Runtime::<Fr>::new();
    let mut data_store = StateStore::new();
    let circuit_config = CircuitConfig::default()
        .stack_ops_num(Some(20))
        .locals_ops_num(Some(20));
    let trace = runtime.execute_script(script.clone(), vec![], None, None, &mut data_store)?;
    let witness = runtime.process_execution_trace(
        vec![],
        Some(script),
        None,
        vec![],
        trace,
        circuit_config,
    )?;

    let vm_circuit = VmCircuit {
        witness,
        public_input: None,
    };
    let k = find_best_k(&vm_circuit);

    let prover = MockProver::<Fr>::run(k, &vm_circuit, vec![vec![Fr::zero()]]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}
