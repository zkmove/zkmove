use crate::native_functions::NativeFunction;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;

pub mod eth_data;

pub fn make_all() -> impl IntoIterator<
    Item = (
        AccountAddress,
        Identifier,
        Identifier,
        move_vm_runtime::native_functions::NativeFunction,
    ),
> {
    eth_data::make_all().into_iter().map(|(func_name, func)| {
        (
            AccountAddress::ONE,
            Identifier::new("EthData").unwrap(),
            Identifier::new(func_name).unwrap(),
            func,
        )
    })
}

pub fn make_all_field_version(
) -> impl IntoIterator<Item = (AccountAddress, Identifier, Identifier, NativeFunction)> {
    eth_data::make_all_field_version()
        .into_iter()
        .map(|(func_name, func)| {
            (
                AccountAddress::ONE,
                Identifier::new("EthData").unwrap(),
                Identifier::new(func_name).unwrap(),
                func,
            )
        })
}
