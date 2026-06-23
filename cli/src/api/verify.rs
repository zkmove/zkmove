// Copyright (c) zkMove Authors

//! Local proof verification logic, decoupled from CLI argument parsing and file IO.

use crate::api::context::ZkMoveContext;
use crate::common::KZGVariant;
use anyhow::Result;
use halo2::proofs::{verify_circuit, KZG};
use log::debug;
use vm_circuit::public_inputs::PublicInputs;

/// Verify a proof locally using the setup verifying key in `ctx`.
pub fn verify(
    ctx: &ZkMoveContext,
    variant: KZGVariant,
    proof: &[u8],
    pubs_bytes: &[u8],
) -> Result<()> {
    let public_inputs = PublicInputs::from_bytes(pubs_bytes);

    let kzg_scheme = match variant {
        KZGVariant::GWC => KZG::GWC,
        KZGVariant::SHPLONK => KZG::SHPLONK,
    };
    verify_circuit(&public_inputs, &ctx.params, &ctx.vk, proof, kzg_scheme)
        .map_err(|e| anyhow::anyhow!("verify proof failed: {:?}", e))?;

    debug!("Proof verified successfully");
    Ok(())
}
