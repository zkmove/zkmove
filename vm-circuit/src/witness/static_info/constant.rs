use crate::witness::utils::ModuleIdMapping;
use move_binary_format::access::ModuleAccess;
use move_binary_format::CompiledModule;
use move_core_types::value::MoveValue;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ConstantInfo {
    pub module_index: usize,
    pub constant_index: usize,
    pub value: MoveValue,
}

pub(crate) fn parse_dependency(
    module_id_mapping: &ModuleIdMapping,
    deps: &[CompiledModule],
) -> Vec<ConstantInfo> {
    deps.iter()
        .flat_map(|module| {
            module
                .constant_pool()
                .iter()
                .enumerate()
                .map(|(idx, constant)| {
                    #[allow(clippy::expect_fun_call)]
                    let value = constant.deserialize_constant().expect(&format!(
                        "deserialize_constant {} at module {:?} should not fail",
                        idx,
                        module.self_id()
                    ));
                    ConstantInfo {
                        module_index: module_id_mapping.get_module_index(&module.self_id()),
                        constant_index: idx,
                        value,
                    }
                })
        })
        .collect()
}
