// Copyright (c) zkMove Authors

use crate::interpreter::Interpreter;
use crate::runtime::Runtime;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use movelang::state::StateStore;
use movelang::value::Value;
use vm_circuit::chips::execution_chip::opcode::Opcode;
use vm_circuit::circuit::VmCircuit;
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
    let mut blob = vec![];
    script.serialize(&mut blob).expect("script must serialize");

    let runtime = Runtime::<Fp>::new();
    let mut data_store = StateStore::new();
    let mut interp = Interpreter::<Fp>::new();

    let (entry, arg_types) = runtime
        .loader()
        .load_script(&blob, &data_store)
        .map_err(|e| {
            error!("load script failed: {:?}", e);
            RuntimeError::new(StatusCode::ScriptLoadingError)
        })
        .unwrap();

    let mut exec_steps = Vec::new();
    let mut rw_operations = Vec::new();
    let mut func_calls = Vec::new();
    let mut arith_operations = Vec::new();
    interp
        .run_script(
            entry,
            None,
            arg_types,
            runtime.loader(),
            &mut data_store,
            &mut exec_steps,
            &mut rw_operations,
            &mut func_calls,
            &mut arith_operations,
        )
        .unwrap();

    let expected_step_0 = ExecutionStep {
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 0,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_1 = ExecutionStep {
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 1,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_2 = ExecutionStep {
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        call_index: 0,
        locals_index: 0,
        gc: 2,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_3 = ExecutionStep {
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 5,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_4 = ExecutionStep {
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_5 = ExecutionStep {
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };

    assert_eq!(exec_steps[0], expected_step_0, "result is not expected");
    assert_eq!(exec_steps[1], expected_step_1, "result is not expected");
    assert_eq!(exec_steps[2], expected_step_2, "result is not expected");
    assert_eq!(exec_steps[3], expected_step_3, "result is not expected");
    assert_eq!(exec_steps[4], expected_step_4, "result is not expected");
    assert_eq!(exec_steps[5], expected_step_5, "result is not expected");

    let expected_rw_op_0 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: WRITE,
        gc: 0,
    });
    let expected_rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        value: Value::u64(2, None).unwrap(),
        rw: WRITE,
        gc: 1,
    });
    let expected_rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        value: Value::u64(2, None).unwrap(),
        rw: READ,
        gc: 2,
    });
    let expected_rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: READ,
        gc: 3,
    });
    let expected_rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(3, None).unwrap(),
        rw: WRITE,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(3, None).unwrap(),
        rw: READ,
        gc: 5,
    });

    assert_eq!(rw_operations[0], expected_rw_op_0, "result is not expected");
    assert_eq!(rw_operations[1], expected_rw_op_1, "result is not expected");
    assert_eq!(rw_operations[2], expected_rw_op_2, "result is not expected");
    assert_eq!(rw_operations[3], expected_rw_op_3, "result is not expected");
    assert_eq!(rw_operations[4], expected_rw_op_4, "result is not expected");
    assert_eq!(rw_operations[5], expected_rw_op_5, "result is not expected");

    let circuit_config = CircuitConfig::default();
    let witness = Witness::new(
        exec_steps,
        rw_operations,
        bytecodes,
        vec![],
        arith_operations,
        circuit_config,
    );
    let vm_circuit = VmCircuit { witness };
    let k = 10; // todo: how to chose a proper degree
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

    let step_0 = ExecutionStep::<Fp> {
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 0,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_1 = ExecutionStep::<Fp> {
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 1,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_2 = ExecutionStep::<Fp> {
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        call_index: 0,
        locals_index: 0,
        gc: 2,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_3 = ExecutionStep::<Fp> {
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 5,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_4 = ExecutionStep::<Fp> {
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_5 = ExecutionStep::<Fp> {
        opcode: Opcode::Nop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_6 = ExecutionStep::<Fp> {
        opcode: Opcode::Nop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let step_7 = ExecutionStep::<Fp> {
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };

    let exec_steps = vec![
        step_0, step_1, step_2, step_3, step_4, step_5, step_6, step_7,
    ];

    let rw_op_0 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: WRITE,
        gc: 0,
    });
    let rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        value: Value::u64(2, None).unwrap(),
        rw: WRITE,
        gc: 1,
    });
    let rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        value: Value::u64(2, None).unwrap(),
        rw: READ,
        gc: 2,
    });
    let rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: READ,
        gc: 3,
    });
    let rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(3, None).unwrap(),
        rw: WRITE,
        gc: 4,
    });
    let rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(3, None).unwrap(),
        rw: READ,
        gc: 5,
    });
    let fake_rw_op = RWOperation::<Fp>::LocalsOp(LocalsOp {
        call_index: 0,
        index: 0,
        value: Value::u64(3, None).unwrap(),
        rw: WRITE,
        gc: 6,
    });

    let rw_operations = vec![
        rw_op_0, rw_op_1, rw_op_2, rw_op_3, rw_op_4, rw_op_5, fake_rw_op,
    ];

    let circuit_config = CircuitConfig::default();
    let witness = Witness::new(
        exec_steps,
        rw_operations,
        bytecodes,
        vec![],
        vec![],
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
    let circuit_config = CircuitConfig::default().steps_num(Some(8));
    let witness = runtime.execute_script(script, vec![], None, &mut data_store, circuit_config)?;

    let vm_circuit = VmCircuit { witness };
    let k = runtime.find_best_k(&vm_circuit, vec![])?;

    let expected_step_0 = ExecutionStep {
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 0,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_1 = ExecutionStep {
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 1,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_2 = ExecutionStep {
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        call_index: 0,
        locals_index: 0,
        gc: 2,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_3 = ExecutionStep {
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 5,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_4 = ExecutionStep {
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
    };
    let expected_step_5 = ExecutionStep {
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary_1: None,
        auxiliary_2: None,
        auxiliary_3: None,
        auxiliary_4: None,
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
        value: Value::u64(1, None).unwrap(),
        rw: WRITE,
        gc: 0,
    });
    let expected_rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        value: Value::u64(2, None).unwrap(),
        rw: WRITE,
        gc: 1,
    });
    let expected_rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        value: Value::u64(2, None).unwrap(),
        rw: READ,
        gc: 2,
    });
    let expected_rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: READ,
        gc: 3,
    });
    let expected_rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(3, None).unwrap(),
        rw: WRITE,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Value::u64(3, None).unwrap(),
        rw: READ,
        gc: 5,
    });

    let rw_ops = &vm_circuit.witness.rw_operations.0;
    assert_eq!(rw_ops[0], expected_rw_op_0, "result is not expected");
    assert_eq!(rw_ops[1], expected_rw_op_1, "result is not expected");
    assert_eq!(rw_ops[2], expected_rw_op_2, "result is not expected");
    assert_eq!(rw_ops[3], expected_rw_op_3, "result is not expected");
    assert_eq!(rw_ops[4], expected_rw_op_4, "result is not expected");
    assert_eq!(rw_ops[5], expected_rw_op_5, "result is not expected");

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
    let witness = runtime.execute_script(script, vec![], None, &mut data_store, circuit_config)?;

    let vm_circuit = VmCircuit { witness };
    let k = runtime.find_best_k(&vm_circuit, vec![])?;

    let prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}
