use crate::runtime::Runtime;
use crate::value::Value::Variable;
use crate::value::{FVariable, Value};
use crate::vm_circuit::chips::bytecode::Opcode;
use crate::vm_circuit::circuit_inputs::RW::{READ, WRITE};
use crate::vm_circuit::circuit_inputs::{
    CircuitInputs, ExecutionStep, LocalsOp, RWLookUpTable, RWOperation, StackOp,
};
use crate::vm_circuit::execution_circuit::ExecutionCircuit;
use crate::vm_circuit::interpreter::Interpreter;
use crate::vm_circuit::memory_circuit::MemoryCircuit;
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use movelang::state::{State, StateStore};
use movelang::value::MoveValueType;

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
    let mut blob = vec![];
    script.serialize(&mut blob).expect("script must serialize");

    let runtime = Runtime::new();
    let mut data_store = StateStore::new();
    let mut interp = Interpreter::<Fp>::new();
    let mut state = State::new(&mut data_store);

    let (entry, arg_types) = runtime
        .loader()
        .load_script(&blob, &mut state)
        .map_err(|e| {
            error!("load script failed: {:?}", e);
            RuntimeError::new(StatusCode::ScriptLoadingError)
        })
        .unwrap();

    let mut exec_steps = Vec::new();
    let mut rw_operations = Vec::new();
    interp
        .run_script(
            entry,
            None,
            arg_types,
            runtime.loader(),
            &mut exec_steps,
            &mut rw_operations,
        )
        .unwrap();

    let expected_step_0 = ExecutionStep {
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 0,
        auxiliary: None,
    };
    let expected_step_1 = ExecutionStep {
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 1,
        auxiliary: None,
    };
    let expected_step_2 = ExecutionStep {
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        call_index: 0,
        locals_index: 0,
        gc: 2,
        auxiliary: None,
    };
    let expected_step_3 = ExecutionStep {
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 5,
        auxiliary: None,
    };
    let expected_step_4 = ExecutionStep {
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        auxiliary: None,
    };

    assert_eq!(exec_steps[0], expected_step_0, "result is not expected");
    assert_eq!(exec_steps[1], expected_step_1, "result is not expected");
    assert_eq!(exec_steps[2], expected_step_2, "result is not expected");
    assert_eq!(exec_steps[3], expected_step_3, "result is not expected");
    assert_eq!(exec_steps[4], expected_step_4, "result is not expected");

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
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(3)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: WRITE,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(3)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: READ,
        gc: 5,
    });

    assert_eq!(rw_operations[0], expected_rw_op_0, "result is not expected");
    assert_eq!(rw_operations[1], expected_rw_op_1, "result is not expected");
    assert_eq!(rw_operations[2], expected_rw_op_2, "result is not expected");
    assert_eq!(rw_operations[3], expected_rw_op_3, "result is not expected");
    assert_eq!(rw_operations[4], expected_rw_op_4, "result is not expected");
    assert_eq!(rw_operations[5], expected_rw_op_5, "result is not expected");

    let circuit_inputs = CircuitInputs::new(exec_steps, RWLookUpTable(rw_operations));
    let circuit_exe = ExecutionCircuit {
        circuit_inputs: circuit_inputs.clone(),
    };
    let k = 10; // todo: how to chose a proper degree
    let prover = MockProver::<Fp>::run(k, &circuit_exe, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::SynthesisError)
    })?;
    assert_eq!(prover.verify(), Ok(()));

    let circuit_mem = MemoryCircuit { circuit_inputs };
    let k = 10;
    let prover = MockProver::<Fp>::run(k, &circuit_mem, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::SynthesisError)
    })?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}

#[test]
fn test_fake_rw_operation() -> VmResult<()> {
    logger::init_for_test();

    let step_0 = ExecutionStep::<Fp> {
        opcode: Opcode::LdU64,
        pc: 0,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 0,
        auxiliary: None,
    };
    let step_1 = ExecutionStep::<Fp> {
        opcode: Opcode::LdU64,
        pc: 1,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 1,
        auxiliary: None,
    };
    let step_2 = ExecutionStep::<Fp> {
        opcode: Opcode::Add,
        pc: 2,
        stack_size: 2,
        call_index: 0,
        locals_index: 0,
        gc: 2,
        auxiliary: None,
    };
    let step_3 = ExecutionStep::<Fp> {
        opcode: Opcode::Pop,
        pc: 3,
        stack_size: 1,
        call_index: 0,
        locals_index: 0,
        gc: 5,
        auxiliary: None,
    };
    let step_4 = ExecutionStep::<Fp> {
        opcode: Opcode::Ret,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        auxiliary: None,
    };

    let mut exec_steps = Vec::new();
    exec_steps.push(step_0);
    exec_steps.push(step_1);
    exec_steps.push(step_2);
    exec_steps.push(step_3);
    exec_steps.push(step_4);

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
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(3)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: WRITE,
        gc: 4,
    });
    let rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(3)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: READ,
        gc: 5,
    });
    let fake_rw_op = RWOperation::<Fp>::LocalsOp(LocalsOp {
        call_index: 0,
        index: 0,
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(3)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: WRITE,
        gc: 6,
    });

    let mut rw_operations = Vec::new();
    rw_operations.push(rw_op_0);
    rw_operations.push(rw_op_1);
    rw_operations.push(rw_op_2);
    rw_operations.push(rw_op_3);
    rw_operations.push(rw_op_4);
    rw_operations.push(rw_op_5);
    rw_operations.push(fake_rw_op);

    let circuit_inputs = CircuitInputs::new(exec_steps, RWLookUpTable(rw_operations));
    let circuit_exe = ExecutionCircuit {
        circuit_inputs: circuit_inputs.clone(),
    };
    let k = 10;
    let prover = MockProver::<Fp>::run(k, &circuit_exe, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::SynthesisError)
    })?;
    assert_eq!(prover.verify(), Ok(()));

    let circuit_mem = MemoryCircuit { circuit_inputs };
    let k = 10;
    let prover = MockProver::<Fp>::run(k, &circuit_mem, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::SynthesisError)
    })?;
    assert_ne!(prover.verify(), Ok(()));

    Ok(())
}
