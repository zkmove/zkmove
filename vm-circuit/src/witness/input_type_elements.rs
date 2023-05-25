use crate::witness::call_trace_table::FunctionName;
use move_binary_format::file_format::Bytecode;
use move_binary_format::normalized::Type;
use move_core_types::language_storage::ModuleId;

#[derive(Clone, Debug)]
pub struct GenericTypeMaterialization {
    pub execution_step_index: usize,
    pub op: Bytecode,
    pub frame_index: u64,
    pub instantiation_point_id: u128,
    pub instantiation_point_pc: u64,
    pub instantiation_point_module: Option<ModuleId>,
    pub instantiation_point_function: FunctionName,

    pub type_args: Vec<Type>,
}
#[derive(Clone, Debug)]
pub struct InputTypeElement {
    pub ty_arg_pos: u128,
    pub ty_arg_module: u64,
    pub ty_arg_name: u16,
}

#[derive(Clone, Default, Debug)]
pub struct InputTypeElementTableData(pub Vec<InputTypeElement>);
