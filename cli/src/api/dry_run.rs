// Copyright (c) zkMove Authors

//! Witness (execution trace) generation: execute an entry function in the Move VM and
//! capture its footprints.
//!
//! Unlike `move sandbox run`, this is a *dry run*: resource effects are intentionally
//! NOT committed back to storage. Each invocation is an independent, reproducible
//! execution of a single entry function (which is exactly what the circuit proves), so
//! cross-invocation state would only make witness generation non-deterministic.

use crate::api::context::{EntryArgument, ZkMoveContext};
use anyhow::{bail, Result};
use move_binary_format::errors::PartialVMError;
use move_cli::sandbox::utils::get_gas_status;
use move_compiler::compiled_unit::CompiledUnitEnum;
use move_core_types::{
    account_address::AccountAddress,
    identifier::IdentStr,
    language_storage::{ModuleId, TypeTag},
    resolver::MoveResolver,
    transaction_argument::convert_txn_args,
    value::MoveValue,
};
use move_package::compilation::compiled_package::CompiledPackage;
use move_stdlib::natives::{all_natives, nursery_natives, GasParameters, NurseryGasParameters};
use move_vm_runtime::{
    module_traversal::{TraversalContext, TraversalStorage},
    move_vm::MoveVM,
};
use move_vm_test_utils::InMemoryStorage;
use witness::static_info::Footprints;

/// The address `MoveStdlib` native functions are registered under.
const STDLIB_ADDRESS: &str = "0x1";

/// Public SDK dry-run API.
///
/// This only checks whether the entry function executes and captures footprints. The
/// witness itself is intentionally not returned from the public API; proving repeats
/// the dry-run internally.
pub fn dry_run(
    ctx: &ZkMoveContext,
    module_id: &ModuleId,
    function_name: &str,
    args: &[EntryArgument],
) -> Result<()> {
    generate_witness(ctx, module_id, function_name, args).map(|_| ())
}

/// Generate the witness used internally by proving.
pub(crate) fn generate_witness(
    ctx: &ZkMoveContext,
    module_id: &ModuleId,
    function_name: &str,
    args: &[EntryArgument],
) -> Result<Footprints> {
    let storage = prepare_in_memory_storage(&ctx.package)?;
    generate_witness_in_storage(&storage, module_id, function_name, Vec::new(), args, &[])
}

/// Load compiled package modules into an in-memory Move VM resolver.
pub fn prepare_in_memory_storage(package: &CompiledPackage) -> Result<InMemoryStorage> {
    let mut storage = InMemoryStorage::new();
    for cu in package.all_modules() {
        if let CompiledUnitEnum::Module(named) = &cu.unit {
            let id = named.module.self_id();
            storage.publish_or_overwrite_module(id, cu.unit.serialize(None));
        }
    }
    Ok(storage)
}

/// Execute the entry function `module_id::function_name` and return the captured
/// footprints (the witness / execution traces) used for proving.
///
/// The caller owns storage preparation. For the CLI this is an `OnDiskStateView`
/// populated from the compiled package, while SDK callers can provide any resolver.
pub fn generate_witness_in_storage<S>(
    state: &S,
    module_id: &ModuleId,
    function_name: &str,
    type_args: Vec<TypeTag>,
    args: &[EntryArgument],
    signers: &[String],
) -> Result<Footprints>
where
    S: MoveResolver<PartialVMError>,
{
    // Assemble call arguments: leading signer args, then user-provided txn args.
    let signer_addresses = signers
        .iter()
        .map(|s| AccountAddress::from_hex_literal(s))
        .collect::<Result<Vec<_>, _>>()?;
    let vm_args: Vec<Vec<u8>> = convert_txn_args(args);
    let vm_args: Vec<Vec<u8>> = signer_addresses
        .iter()
        .map(|a| {
            MoveValue::Signer(*a)
                .simple_serialize()
                .expect("signer argument must serialize")
        })
        .chain(vm_args)
        .collect();

    let stdlib_addr =
        AccountAddress::from_hex_literal(STDLIB_ADDRESS).expect("stdlib address literal is valid");
    let natives = all_natives(stdlib_addr, GasParameters::zeros())
        .into_iter()
        .chain(nursery_natives(stdlib_addr, NurseryGasParameters::zeros()))
        .collect::<Vec<_>>();

    let cost_table = &move_vm_test_utils::gas_schedule::INITIAL_COST_SCHEDULE;
    let mut gas_status = get_gas_status(cost_table, None)?;

    let vm = MoveVM::new(natives).expect("MoveVM should initialize");
    let mut session = vm.new_session(state);

    let traversal_storage = TraversalStorage::new();
    let function_ident = IdentStr::new(function_name)?;
    session
        .execute_entry_function(
            module_id,
            function_ident,
            type_args,
            vm_args,
            &mut gas_status,
            &mut TraversalContext::new(&traversal_storage),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to execute entry function {}::{}: {:?}",
                module_id,
                function_name,
                e
            )
        })?;

    // Take the footprints and drop the session without `finish()`: this is a dry run, so
    // any resource effects are discarded rather than committed back to storage.
    let footprints = session.footprints();
    if footprints.is_empty() {
        bail!(
            "no footprints captured; ensure move-vm-runtime is built with the `footprint` feature"
        );
    }
    Ok(Footprints(footprints))
}
