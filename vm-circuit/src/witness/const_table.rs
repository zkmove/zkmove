use move_binary_format::access::ModuleAccess;
use move_binary_format::file_format::CompiledScript;
use move_binary_format::CompiledModule;
use move_core_types::value::MoveValue;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ConstantInfo {
    pub module_index: u16,
    pub constant_index: u16,
    pub value: MoveValue,
}

#[derive(Clone, Debug, Default)]
pub struct ConstantTable(pub Vec<ConstantInfo>);

impl<'a> From<(&'a CompiledScript, &'a [CompiledModule])> for ConstantTable {
    fn from((script, deps): (&'a CompiledScript, &'a [CompiledModule])) -> Self {
        ConstantTable(parse_consts(script, deps))
    }
}

fn parse_consts(script: &CompiledScript, deps: &[CompiledModule]) -> Vec<ConstantInfo> {
    let module_const_info = deps.iter().enumerate().flat_map(|(idx, m)| {
        m.constant_pool()
            .iter()
            .enumerate()
            .map(move |(constant_idx, constant)| {
                #[allow(clippy::expect_fun_call)]
                let value = constant.deserialize_constant().expect(&format!(
                    "deserialize_constant {} at module {:?}",
                    constant_idx,
                    m.self_id()
                ));
                ConstantInfo {
                    module_index: idx as u16 + 1, // 0 is preserved for the script
                    constant_index: constant_idx as u16,
                    value,
                }
            })
    });

    script
        .constant_pool
        .iter()
        .enumerate()
        .map(move |(constant_idx, constant)| {
            #[allow(clippy::expect_fun_call)]
            let value = constant
                .deserialize_constant()
                .expect(&format!("deserialize_constant {} at script", constant_idx));
            ConstantInfo {
                module_index: 0u16,
                constant_index: constant_idx as u16,
                value,
            }
        })
        .chain(module_const_info)
        .collect()
}
