use move_binary_format::access::ModuleAccess;
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

impl<T: AsRef<[CompiledModule]>> From<T> for ConstantTable {
    fn from(modules: T) -> Self {
        ConstantTable(parse_consts(modules.as_ref()))
    }
}

fn parse_consts(mods: &[CompiledModule]) -> Vec<ConstantInfo> {
    mods.iter()
        .enumerate()
        .flat_map(|(idx, m)| {
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
                        module_index: idx as u16 + 1,
                        constant_index: constant_idx as u16,
                        value,
                    }
                })
        })
        .collect()
}
