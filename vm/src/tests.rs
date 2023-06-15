// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::pasta::Fp;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use move_binary_format::CompiledModule;
use movelang::state::StateStore;
use movelang::value::{PrimitiveValue, Value};
use movelang::word::ValueHeader;
use vm_circuit::chips::execution_chip::opcode::Opcode;
use vm_circuit::circuit::VmCircuit;
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
    let arith_operations = ArithOperations::from((&script, deps)).0;
    let mut blob = vec![];
    script.serialize(&mut blob).expect("script must serialize");

    let runtime = Runtime::<Fp>::new();
    let mut data_store = StateStore::new();
    let mut interp = Interpreter::<Fp>::new();

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
        .run_script(
            &script,
            entry,
            ty_arguments,
            None,
            None,
            arg_types,
            runtime.loader(),
            &mut data_store,
            &mut exec_steps,
            &mut rw_operations,
            &mut generic_type_infos,
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
        gc: 2,
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
        gc: 4,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
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
        gc: 10,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: Some(Value::u64(2u64)),
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
        gc: 12,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
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
        gc: 12,
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

    let expected_rw_op_0 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let expected_rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(1)),

        rw: WRITE,
        gc: 1,
    });
    let expected_rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 2,
    });
    let expected_rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(2)),

        rw: WRITE,
        gc: 3,
    });
    let expected_rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(2)),

        rw: READ,
        gc: 5,
    });
    let expected_rw_op_6 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let expected_rw_op_7 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(1)),

        rw: READ,
        gc: 7,
    });
    let expected_rw_op_8 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 8,
    });
    let expected_rw_op_9 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(3)),

        rw: WRITE,
        gc: 9,
    });
    let expected_rw_op_10 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 10,
    });
    let expected_rw_op_11 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(3)),

        rw: READ,
        gc: 11,
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
    let vm_circuit = VmCircuit { witness };
    let k = 10;
    let prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
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
        gc: 2,
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
        gc: 4,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
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
        gc: 10,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: Some(Value::u64(2u64)),
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
        gc: 12,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_5 = ExecutionStep::<Fp> {
        context_id: 1,
        opcode: Opcode::Nop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 12,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
        auxiliary_5: None,
        data: None,
    };
    let step_6 = ExecutionStep::<Fp> {
        context_id: 1,
        opcode: Opcode::Nop,
        pc: 4,
        stack_size: 0,
        frame_index: 0,
        locals_index: 0,
        gc: 12,
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
        gc: 12,
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

    let rw_op_0 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(1)),

        rw: WRITE,
        gc: 1,
    });
    let rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 2,
    });
    let rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(2)),

        rw: WRITE,
        gc: 3,
    });
    let rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 4,
    });
    let rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(2)),

        rw: READ,
        gc: 5,
    });
    let rw_op_6 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let rw_op_7 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(1)),

        rw: READ,
        gc: 7,
    });
    let rw_op_8 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 8,
    });
    let rw_op_9 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(3)),

        rw: WRITE,
        gc: 9,
    });
    let rw_op_10 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 10,
    });
    let rw_op_11 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(3)),

        rw: READ,
        gc: 11,
    });
    let fake_rw_op = RWOperation::<Fp>::LocalsOp(LocalsOp {
        frame_index: 0,
        index: 0,
        address_ext_0: 0,
        value: Some(PrimitiveValue::u64(3)),

        rw: WRITE,
        gc: 12,
    });

    let rw_operations = vec![
        rw_op_0, rw_op_1, rw_op_2, rw_op_3, rw_op_4, rw_op_5, rw_op_6, rw_op_7, rw_op_8, rw_op_9,
        rw_op_10, rw_op_11, fake_rw_op,
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
    let vm_circuit = VmCircuit { witness };
    let k = 10;
    let prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
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

    let runtime = Runtime::<Fp>::new();
    let mut data_store = StateStore::new();
    let circuit_config = CircuitConfig::default().max_step_row(Some(100));
    let witness = runtime.execute_script(
        script,
        vec![],
        vec![],
        None,
        None,
        &mut data_store,
        circuit_config,
    )?;

    let vm_circuit = VmCircuit { witness };
    let k = runtime.find_best_k(&vm_circuit, vec![])?;

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
        gc: 2,
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
        gc: 4,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
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
        gc: 10,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: Some(Value::u64(2u64)),
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
        gc: 12,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
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
        gc: 12,
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

    let expected_rw_op_0 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let expected_rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(1)),

        rw: WRITE,
        gc: 1,
    });
    let expected_rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 2,
    });
    let expected_rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(2)),

        rw: WRITE,
        gc: 3,
    });
    let expected_rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(2)),

        rw: READ,
        gc: 5,
    });
    let expected_rw_op_6 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let expected_rw_op_7 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(1)),

        rw: READ,
        gc: 7,
    });
    let expected_rw_op_8 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 8,
    });
    let expected_rw_op_9 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(3)),

        rw: WRITE,
        gc: 9,
    });
    let expected_rw_op_10 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 10,
    });
    let expected_rw_op_11 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        value: Some(PrimitiveValue::u64(3)),

        rw: READ,
        gc: 11,
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

    let prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
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

    let runtime = Runtime::<Fp>::new();
    let mut data_store = StateStore::new();
    let circuit_config = CircuitConfig::default()
        .stack_ops_num(Some(20))
        .locals_ops_num(Some(20));
    let witness = runtime.execute_script(
        script,
        vec![],
        vec![],
        None,
        None,
        &mut data_store,
        circuit_config,
    )?;

    let vm_circuit = VmCircuit { witness };
    let k = runtime.find_best_k(&vm_circuit, vec![])?;

    let prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}
