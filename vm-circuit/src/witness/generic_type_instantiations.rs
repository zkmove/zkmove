use crate::witness::call_trace_table::FunctionName;
use move_binary_format::file_format::Bytecode;
use move_binary_format::normalized::Type;
use move_core_types::language_storage::ModuleId;

#[derive(Clone, Debug)]
pub struct GenericTypeInstantiation {
    pub execution_step_index: usize,
    pub op: Bytecode,
    pub frame_index: u64,
    pub instantiation_point_pc: u64,
    pub call_id: u128,
    pub instantiation_point_module: Option<ModuleId>,
    pub instantiation_point_function: FunctionName,

    pub type_args: Vec<Type>,
    pub inst_type_args: Vec<Type>,
}
#[derive(Clone, Debug)]
pub struct GenericTypeInstantiationTableItem {
    pub frame_index_plus_one: u64,
    pub call_id: u128,

    pub instantiation_point_module: u64,
    pub instantiation_point_function: u16,
    pub instantiation_point_pc: u64,

    pub ty_arg_pos: u128,
    pub ty_arg_module: u64,
    pub ty_arg_name: u16,
}

#[derive(Clone, Default, Debug)]
pub struct GenericTypeInstantiationTableData(pub Vec<GenericTypeInstantiationTableItem>);
