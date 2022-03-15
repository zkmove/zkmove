use crate::runtime::Runtime;
use crate::turing_complete::chips::vm_circuit::VmCircuit;
use crate::turing_complete::circuit_inputs::RW::{READ, WRITE};
use crate::turing_complete::circuit_inputs::{
    CircuitInputs, ExecutionStep, RWLookUpTable, RWOperation, StackOp,
};
use crate::turing_complete::interpreter::Interpreter;
use crate::value::Value::Variable;
use crate::value::{FVariable, Value};
use error::{RuntimeError, StatusCode, VmResult};
use halo2::arithmetic::FieldExt;
use halo2::dev::MockProver;
use halo2::pasta::Fp;
use logger::prelude::*;
use move_binary_format::file_format::{empty_script, Bytecode};
use movelang::state::{State, StateStore};
use movelang::value::MoveValueType;

#[test]
fn test_execution_step() -> VmResult<()> {
    logger::init_for_test();
    let mut script = empty_script();
    script.code.code = vec![
        Bytecode::LdU64(1u64),
        Bytecode::LdU64(2u64),
        Bytecode::Add,
        Bytecode::Pop,
        Bytecode::Ret,
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
        bytecode: Bytecode::LdU64(1),
        pc: 0,
        stack_size: 0,
        call_index: 0,
        gc: 0,
    };
    let expected_step_1 = ExecutionStep {
        bytecode: Bytecode::LdU64(2),
        pc: 1,
        stack_size: 1,
        call_index: 0,
        gc: 1,
    };
    let expected_step_2 = ExecutionStep {
        bytecode: Bytecode::Add,
        pc: 2,
        stack_size: 2,
        call_index: 0,
        gc: 2,
    };
    let expected_step_3 = ExecutionStep {
        bytecode: Bytecode::Pop,
        pc: 3,
        stack_size: 1,
        call_index: 0,
        gc: 5,
    };
    let expected_step_4 = ExecutionStep {
        bytecode: Bytecode::Ret,
        pc: 4,
        stack_size: 0,
        call_index: 0,
        gc: 6,
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
            value: Some(Fp::from_u64(3)),
            cell: None,
            ty: MoveValueType::U64,
        }),
        rw: WRITE,
        gc: 4,
    });
    let expected_rw_op_5 = RWOperation::<Fp>::StackOp(StackOp {
        address: 0,
        value: Variable(FVariable::<Fp> {
            value: Some(Fp::from_u64(3)),
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
    let circuit = VmCircuit { circuit_inputs };
    let k = 20; // todo: how to chose a proper degree
    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).map_err(|e| {
        debug!("Prover Error: {:?}", e);
        RuntimeError::new(StatusCode::SynthesisError)
    })?;
    Ok(())
}
