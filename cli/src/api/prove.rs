// Copyright (c) zkMove Authors

//! Proof generation logic, decoupled from CLI argument parsing and file IO.

use crate::api::circuit::build_circuit_from_trace;
use crate::api::setup::{EntryArgument, VmCircuitContext};
use crate::api::witness as witness_api;
use crate::common::KZGVariant;
use anyhow::{bail, Context, Result};
use halo2::proofs::{prove_circuit, KZG};
use move_core_types::language_storage::ModuleId;
use vm_circuit::public_inputs::PublicInputs;
use witness::static_info::Footprints;

/// The artifacts produced by [`prove`].
pub struct ProveOutput {
    /// The serialized proof bytes.
    pub proof: Vec<u8>,
    /// The serialized public inputs (instance) bytes.
    pub instance: Vec<u8>,
}

/// Generate a proof by dry-running the entry function and proving the resulting witness.
pub fn prove(
    ctx: &VmCircuitContext,
    module_id: &ModuleId,
    function_name: &str,
    args: &[EntryArgument],
    variant: KZGVariant,
) -> Result<ProveOutput> {
    let traces = witness_api::generate_witness(&ctx.package, module_id, function_name, args)?;
    prove_with_witness(ctx, &traces, variant)
}

/// Generate a proof for an already captured witness.
///
/// This keeps the old CLI witness-file flow as a thin compatibility layer; SDK callers
/// should use [`prove`] so the dry-run happens internally.
pub fn prove_with_witness(
    ctx: &VmCircuitContext,
    traces: &Footprints,
    variant: KZGVariant,
) -> Result<ProveOutput> {
    let witness_entry = traces.entry().context("Entry not found in witness")?;
    if witness_entry != ctx.entry_info {
        bail!(
            "witness entry {:?} does not match setup entry {:?}",
            witness_entry,
            ctx.entry_info
        );
    }

    let (circuit, _circuit_guard) =
        build_circuit_from_trace(&ctx.package, traces, ctx.config.clone(), &ctx.pubs_indices)?;

    let args = traces.args().context("Arguments not found in witness")?;
    let public_inputs = PublicInputs::new(&args, &ctx.pubs_indices);

    let kzg_scheme = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };

    let proof = prove_circuit(
        (*circuit).clone(),
        &public_inputs,
        &ctx.params,
        &ctx.pk,
        kzg_scheme,
    )
    .map_err(|e| anyhow::anyhow!("proof generation failed: {:?}", e))?;

    Ok(ProveOutput {
        proof,
        instance: public_inputs.to_bytes(),
    })
}
