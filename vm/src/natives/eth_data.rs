use crate::native_functions::{NativeContext, NativeFunction};
use error::VmResult;
use halo2_proofs::halo2curves::FieldExt;
use move_vm_types::loaded_data::runtime_types::Type;
use movelang::value::Value;
use std::collections::VecDeque;
use std::sync::Arc;

pub fn native_get_block_hash<F: FieldExt>(
    _context: &mut NativeContext<F>,
    ty_args: Vec<Type>,
    args: VecDeque<Value<F>>,
) -> VmResult<Value<F>> {
    debug_assert_eq!(ty_args.len(), 0);
    debug_assert_eq!(args.len(), 1);

    //let _block_number = popq_arg!(args, u64);
    let bytes =
        hex::decode("fdf1e0fc8faa951020a6d2fb332096f405affaf54a44c2345ddfdb02e687a24e").unwrap();
    let ret_ = Value::<F>::vector_u8(bytes);
    Ok(ret_)
}

pub fn make_all_field_version<F: FieldExt>() -> impl IntoIterator<Item = (String, NativeFunction<F>)>
{
    fn make_native_get_block_hash<F: FieldExt>() -> NativeFunction<F> {
        Arc::new(native_get_block_hash)
    }
    [("get_block_hash".to_string(), make_native_get_block_hash())]
}

pub fn make_all(
) -> impl IntoIterator<Item = (String, move_vm_runtime::native_functions::NativeFunction)> {
    fn native_fake_impl() -> move_vm_runtime::native_functions::NativeFunction {
        Arc::new(|_c, _t, _arg| unimplemented!())
    }

    [("get_block_hash".to_string(), native_fake_impl())]
}
