// Copyright (c) zkMove Authors

use crate::chips::execution_chip::opcode::Opcode;
use crate::circuit::VmCircuit;
use crate::witness::execution_steps::ExecutionStep;
use crate::witness::rw_operations::RW::{READ, WRITE};
use crate::witness::rw_operations::{LocalsOp, RWOperation, StackOp};
use crate::witness::{CircuitConfig, Witness};
use error::{RuntimeError, StatusCode, VmResult};
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use logger::prelude::*;
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode as MoveBytecode;
use movelang::value::{SimpleValue, Value};
use movelang::value_ext::ValueHeader;

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
