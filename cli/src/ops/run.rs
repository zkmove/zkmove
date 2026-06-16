// Copyright (c) zkMove Authors

//! Witness (execution trace) generation: execute an entry function in the Move VM and
//! capture its footprints.
//!
//! Unlike `move sandbox run`, this is a *dry run*: resource effects are intentionally
//! NOT committed back to storage. Each invocation is an independent, reproducible
//! execution of a single entry function (which is exactly what the circuit proves), so
//! cross-invocation state would only make witness generation non-deterministic.

use crate::common::load_package;
use anyhow::{bail, Result};
use move_cli::sandbox::utils::{get_gas_status, OnDiskStateView};
use move_compiler::compiled_unit::CompiledUnitEnum;
use move_core_types::{
    account_address::AccountAddress,
    identifier::IdentStr,
    language_storage::{ModuleId, TypeTag},
    transaction_argument::{convert_txn_args, TransactionArgument},
    value::MoveValue,
};
use move_stdlib::natives::{all_natives, nursery_natives, GasParameters, NurseryGasParameters};
use move_vm_runtime::{
    module_traversal::{TraversalContext, TraversalStorage},
    move_vm::MoveVM,
};
use std::path::Path;
use witness::static_info::Footprints;

const DEFAULT_STORAGE_DIR: &str = "storage";
/// The address `MoveStdlib` native functions are registered under.
const STDLIB_ADDRESS: &str = "0x1";

/// Execute the entry function `module_id::function_name` and return the captured
/// footprints (the witness / execution traces) used for proving.
///
/// All compiled modules of the package (root + dependencies) are preloaded into an
/// on-disk state view rooted at `<package_path>/storage`, so a separate
/// `move sandbox publish` is not required.
pub fn generate_witness(
    package_path: &Path,
    module_id: &ModuleId,
    function_name: &str,
    type_args: Vec<TypeTag>,
    txn_args: &[TransactionArgument],
    signers: &[String],
) -> Result<Footprints> {
    let package = load_package(package_path)?;

    let storage_dir = package_path.join(DEFAULT_STORAGE_DIR);
    let state = OnDiskStateView::create(package_path, &storage_dir)?;

    // Write all compiled modules (root + deps) into storage, overwriting any existing
    // copies. The freshly compiled package is the source of truth, so a rebuilt package
    // is never executed against stale bytecode left over in `storage/`.
    for cu in package.all_modules() {
        if let CompiledUnitEnum::Module(named) = &cu.unit {
            let id = named.module.self_id();
            state.save_module(&id, &cu.unit.serialize(None))?;
        }
    }

    // Assemble call arguments: leading signer args, then user-provided txn args.
    let signer_addresses = signers
        .iter()
        .map(|s| AccountAddress::from_hex_literal(s))
        .collect::<Result<Vec<_>, _>>()?;
    let vm_args: Vec<Vec<u8>> = convert_txn_args(txn_args);
    let args: Vec<Vec<u8>> = signer_addresses
        .iter()
        .map(|a| {
            MoveValue::Signer(*a)
                .simple_serialize()
                .expect("signer argument must serialize")
        })
        .chain(vm_args)
        .collect();

    let stdlib_addr = AccountAddress::from_hex_literal(STDLIB_ADDRESS)
        .expect("stdlib address literal is valid");
    let natives = all_natives(stdlib_addr, GasParameters::zeros())
        .into_iter()
        .chain(nursery_natives(stdlib_addr, NurseryGasParameters::zeros()))
        .collect::<Vec<_>>();

    let cost_table = &move_vm_test_utils::gas_schedule::INITIAL_COST_SCHEDULE;
    let mut gas_status = get_gas_status(cost_table, None)?;

    let vm = MoveVM::new(natives).expect("MoveVM should initialize");
    let mut session = vm.new_session(&state);

    let traversal_storage = TraversalStorage::new();
    let function_ident = IdentStr::new(function_name)?;
    session
        .execute_entry_function(
            module_id,
            function_ident,
            type_args,
            args,
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
        bail!("no footprints captured; ensure move-vm-runtime is built with the `footprint` feature");
    }
    Ok(Footprints(footprints))
}
