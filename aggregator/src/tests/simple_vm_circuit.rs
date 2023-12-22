use error::{RuntimeError, StatusCode};
use move_binary_format::file_format::empty_script;
use move_binary_format::file_format::Bytecode;
use move_binary_format::CompiledModule;
use movelang::generic_call_graph::generate_for_script;
use types::Field;
use vm::interpreter::Interpreter;
use vm::runtime::Runtime;
use vm::state::StateStore;
use vm_circuit::circuit::VmCircuit;
use vm_circuit::witness::arith_operations::ArithOperations;
use vm_circuit::witness::{CircuitConfig, Witness};

pub struct SimpleVmCircuit<F: Field> {
    circuit: VmCircuit<F>,
}

impl<F: Field> SimpleVmCircuit<F> {
    pub fn new() -> Self {
        let mut script = empty_script();
        script.code.code = vec![
            Bytecode::LdU64(1u64),
            Bytecode::LdU64(2u64),
            Bytecode::Add,
            Bytecode::Pop,
            Bytecode::Ret,
        ];
        let bytecodes = (script.clone(), vec![]).into();
        let deps: &[CompiledModule] = &[];
        let arith_operations = ArithOperations::from((Some(&script), deps)).0;
        let mut blob = vec![];
        script.serialize(&mut blob).expect("script must serialize");

        let runtime = Runtime::<F>::new();
        let mut data_store = StateStore::new();
        let mut interp = Interpreter::<F>::new();
        let generic_graph = generate_for_script(&script, &data_store);

        let (entry, ty_arguments) = runtime
            .loader()
            .load_script(&blob, &[], &data_store)
            .map_err(|_| RuntimeError::new(StatusCode::ScriptLoadingError))
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
        let circuit = VmCircuit {
            witness,
            public_input: None,
        };
        SimpleVmCircuit { circuit }
    }

    pub fn circuit(&self) -> &VmCircuit<F> {
        &self.circuit
    }
}
