// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::circuit::VmCircuit;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RW::{READ, WRITE};
use crate::witness::rw_operations::{LocalsOp, RWOperation, StackOp};
use crate::witness::{CircuitConfig, Witness};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::pasta::Fp;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use movelang::value::{PrimitiveValue, Value};
use movelang::word::ValueHeader;

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
        address_ext_1: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 0,
    });
    let rw_op_1 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        address_ext_1: 0,
        value: Some(PrimitiveValue::u64(1)),

        rw: WRITE,
        gc: 1,
    });
    let rw_op_2 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        address_ext_1: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 2,
    });
    let rw_op_3 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        address_ext_1: 0,
        value: Some(PrimitiveValue::u64(2)),

        rw: WRITE,
        gc: 3,
    });
    let rw_op_4 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 0,
        address_ext_1: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 4,
    });
    let rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 1,
        address_ext_0: 1,
        address_ext_1: 0,
        value: Some(PrimitiveValue::u64(2)),

        rw: READ,
        gc: 5,
    });
    let rw_op_6 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        address_ext_1: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 6,
    });
    let rw_op_7 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        address_ext_1: 0,
        value: Some(PrimitiveValue::u64(1)),

        rw: READ,
        gc: 7,
    });
    let rw_op_8 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        address_ext_1: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: WRITE,
        gc: 8,
    });
    let rw_op_9 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        address_ext_1: 0,
        value: Some(PrimitiveValue::u64(3)),

        rw: WRITE,
        gc: 9,
    });
    let rw_op_10 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 0,
        address_ext_1: 0,
        value: Some(ValueHeader::default_for_simple().into()),

        rw: READ,
        gc: 10,
    });
    let rw_op_11 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        address_ext_0: 1,
        address_ext_1: 0,
        value: Some(PrimitiveValue::u64(3)),

        rw: READ,
        gc: 11,
    });
    let fake_rw_op = RWOperation::<Fp>::LocalsOp(LocalsOp {
        frame_index: 0,
        index: 0,
        address_ext_0: 0,
        address_ext_1: 0,
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
