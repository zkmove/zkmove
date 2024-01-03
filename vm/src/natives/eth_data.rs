use crate::native_functions::{NativeContext, NativeFunction};
use error::VmResult;
use move_vm_types::loaded_data::runtime_types::Type;
use movelang::value::Value;
use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;
use types::Field;

#[cfg(not(target_arch = "wasm32"))]
use web3::transports::Http;
#[cfg(not(target_arch = "wasm32"))]
use web3::types::{Address, BlockId, H256, U256};
#[cfg(not(target_arch = "wasm32"))]
use web3::Web3;

#[cfg(not(target_arch = "wasm32"))]
pub fn native_get_block_hash<F: Field>(
    context: &mut NativeContext<F>,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value<F>>,
) -> VmResult<Value<F>> {
    debug_assert_eq!(ty_args.len(), 0);
    debug_assert_eq!(args.len(), 1);
    let block_number = args
        .pop_back()
        .unwrap()
        .castu64()?
        .value()
        .unwrap()
        .get_lower_128() as u64;
    let web3client = context.extensions().get::<&Web3<Http>>();
    let tokio_runtime = context.extensions().get::<&Runtime>();

    let block = tokio_runtime
        .block_on(web3client.eth().block(BlockId::Number(block_number.into())))
        .unwrap();

    let block_hash = if let Some(b) = block {
        b.hash.unwrap()
    } else {
        H256::zero()
    };
    let ret_ = Value::<F>::vector_u8(block_hash.to_fixed_bytes());
    Ok(ret_)
}

#[cfg(target_arch = "wasm32")]
pub fn native_get_block_hash<F: Field>(
    _context: &mut NativeContext<F>,
    ty_args: Vec<Type>,
    args: VecDeque<Value<F>>,
) -> VmResult<Value<F>> {
    debug_assert_eq!(ty_args.len(), 0);
    debug_assert_eq!(args.len(), 1);
    Ok(Value::u64(0))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn native_get_slot<F: Field>(
    context: &mut NativeContext<F>,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value<F>>,
) -> VmResult<Value<F>> {
    debug_assert_eq!(ty_args.len(), 0);
    debug_assert_eq!(args.len(), 3);
    let slot = args
        .pop_back()
        .unwrap()
        .castu128()?
        .value()
        .unwrap()
        .get_lower_128();
    let address = args.pop_back().unwrap().as_vector_u8()?;
    let block_number = args.pop_back().unwrap().value().unwrap().get_lower_128() as u64;

    let web3client = context.extensions().get::<&Web3<Http>>();
    let tokio_runtime = context.extensions().get::<&Runtime>();

    let slot = tokio_runtime
        .block_on(web3client.eth().storage(
            Address::from_slice(address.as_slice()),
            U256::from(slot),
            Some(block_number.into()),
        ))
        .unwrap();

    let ret_ = Value::<F>::vector_u8(slot.to_fixed_bytes());
    Ok(ret_)
}
#[cfg(target_arch = "wasm32")]
pub fn native_get_slot<F: Field>(
    _context: &mut NativeContext<F>,
    ty_args: Vec<Type>,
    args: VecDeque<Value<F>>,
) -> VmResult<Value<F>> {
    debug_assert_eq!(ty_args.len(), 0);
    debug_assert_eq!(args.len(), 3);
    Ok(Value::u64(0))
}

pub fn make_all_field_version<F: Field>() -> impl IntoIterator<Item = (String, NativeFunction<F>)> {
    fn make_native_get_block_hash<F: Field>() -> NativeFunction<F> {
        Arc::new(native_get_block_hash)
    }
    fn make_native_get_slot<F: Field>() -> NativeFunction<F> {
        Arc::new(native_get_slot)
    }
    [
        ("get_block_hash".to_string(), make_native_get_block_hash()),
        ("get_slot".to_string(), make_native_get_slot()),
    ]
}

pub fn make_all(
) -> impl IntoIterator<Item = (String, move_vm_runtime::native_functions::NativeFunction)> {
    fn native_fake_impl() -> move_vm_runtime::native_functions::NativeFunction {
        Arc::new(|_c, _t, _arg| unimplemented!())
    }

    [
        ("get_block_hash".to_string(), native_fake_impl()),
        ("get_slot".to_string(), native_fake_impl()),
    ]
}
