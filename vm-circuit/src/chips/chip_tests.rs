// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::circuit::VmCircuit;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RW::{READ, WRITE};
use crate::witness::rw_operations::{LocalsOp, RWOperation, StackOp};
use crate::witness::{CircuitConfig, Witness};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use movelang::value::MoveValueType;
use types::value::Value::Variable;
use types::value::{FVariable, Value};

#[test]
fn test_fake_rw_operation() -> VmResult<()> {
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
        auxiliary: None,
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
        auxiliary: None,
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
        auxiliary: None,
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
        auxiliary: None,
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
        auxiliary: None,
    };
    let step_5 = ExecutionStep::<Fp> {
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary: None,
    };

    let mut exec_steps = Vec::new();
    exec_steps.push(step_0);
    exec_steps.push(step_1);
    exec_steps.push(step_2);
    exec_steps.push(step_3);
    exec_steps.push(step_4);
    exec_steps.push(step_5);

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

    let circuit_config = CircuitConfig::default();
    let witness = Witness::new(exec_steps, rw_operations, bytecodes, circuit_config);
    let vm_circuit = VmCircuit { witness };
    let k = 10;
    let prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    assert_ne!(prover.verify(), Ok(()));

    Ok(())
}

// after the Witness change this test is dropped because we could not inject a sorted ops.
#[test]
fn test_rw_operation_with_wrong_gc() -> VmResult<()> {
    logger::init_for_test();

    let mut script = empty_script();
    script.code.code = vec![
        MoveBytecode::LdU64(1u64),
        MoveBytecode::LdU64(1u64),
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
        auxiliary: None,
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
        auxiliary: None,
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
        auxiliary: None,
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
        auxiliary: None,
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
        auxiliary: None,
    };
    let step_5 = ExecutionStep::<Fp> {
        opcode: Opcode::Stop,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        locals_index: 0,
        gc: 6,
        module_index: 0,
        function_index: 0,
        auxiliary: None,
    };

    let mut exec_steps = Vec::new();
    exec_steps.push(step_0);
    exec_steps.push(step_1);
    exec_steps.push(step_2);
    exec_steps.push(step_3);
    exec_steps.push(step_4);
    exec_steps.push(step_5);

    let rw_op_0 = StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: WRITE,
        gc: 0,
    };
    let rw_op_1 = StackOp {
        address: 1,
        value: Value::u64(1, None).unwrap(),
        rw: WRITE,
        gc: 1,
    };
    let rw_op_2 = StackOp {
        address: 1,
        value: Value::u64(1, None).unwrap(),
        rw: READ,
        gc: 2,
    };
    let rw_op_3 = StackOp {
        address: 0,
        value: Value::u64(1, None).unwrap(),
        rw: READ,
        gc: 3,
    };
    let rw_op_4 = StackOp {
        address: 0,
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(2)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: WRITE,
        gc: 4,
    };
    let rw_op_5 = StackOp {
        address: 0,
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u128(2)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: READ,
        gc: 5,
    };

    let mut rw_operations = Vec::new();
    rw_operations.push(RWOperation::<Fp>::StackOp(rw_op_0.clone()));
    rw_operations.push(RWOperation::<Fp>::StackOp(rw_op_1.clone()));
    rw_operations.push(RWOperation::<Fp>::StackOp(rw_op_2.clone()));
    rw_operations.push(RWOperation::<Fp>::StackOp(rw_op_3.clone()));
    rw_operations.push(RWOperation::<Fp>::StackOp(rw_op_4.clone()));
    rw_operations.push(RWOperation::<Fp>::StackOp(rw_op_5.clone()));

    // correct sorted ops: 0,3,4,5,1,2
    // wrong sorted ops: 4,5,0,3,1,2
    let mut wrong_sorted_stack_operations = Vec::new();
    wrong_sorted_stack_operations.push(rw_op_4);
    wrong_sorted_stack_operations.push(rw_op_5);
    wrong_sorted_stack_operations.push(rw_op_0);
    wrong_sorted_stack_operations.push(rw_op_3);
    wrong_sorted_stack_operations.push(rw_op_1);
    wrong_sorted_stack_operations.push(rw_op_2);

    let circuit_config = CircuitConfig::default();
    let witness = Witness::new(exec_steps, rw_operations, bytecodes, circuit_config);
    // witness.sorted_stack_ops.0 = wrong_sorted_stack_operations;
    let vm_circuit = VmCircuit { witness };
    let k = 10;
    let _prover = MockProver::<Fp>::run(k, &vm_circuit, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::ProofSystemError(e))
    })?;
    // assert_ne!(prover.verify(), Ok(()));

    Ok(())
}
