// Copyright (c) zkMove Authors

//! SDK-facing context loaded once from app-developer setup artifacts.

use crate::api::circuit::build_empty_circuit;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{pk_read, vk_read, ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use move_core_types::transaction_argument::TransactionArgument;
use move_package::compilation::compiled_package::CompiledPackage;
use std::io::Cursor;
use vm_circuit::CircuitConfigArgs;
use witness::static_info::EntryInfo;

/// SDK entry-function argument.
///
/// This is a semantic alias over Move's transaction argument encoding. The SDK API
/// uses entry/function terminology because end users are not constructing a chain
/// transaction at this stage.
pub type EntryArgument = TransactionArgument;

/// Long-lived SDK context created from app-developer setup artifacts.
pub struct VmCircuitContext {
    pub package: CompiledPackage,
    pub entry_info: EntryInfo,
    pub config: CircuitConfigArgs,
    pub params: ParamsKZG<Bn256>,
    pub pk: ProvingKey<G1Affine>,
    pub vk: VerifyingKey<G1Affine>,
    pub k: u32,
    pub pubs_indices: Vec<usize>,
}

impl VmCircuitContext {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        package: CompiledPackage,
        entry_info: EntryInfo,
        config: CircuitConfigArgs,
        params: ParamsKZG<Bn256>,
        pk: ProvingKey<G1Affine>,
        vk: VerifyingKey<G1Affine>,
        k: u32,
        pubs_indices: Vec<usize>,
    ) -> Self {
        Self {
            package,
            entry_info,
            config,
            params,
            pk,
            vk,
            k,
            pubs_indices,
        }
    }

    /// Load setup artifacts from bytes. The package and circuit metadata are provided by
    /// the embedding app, while params/pk/vk bytes come from app-developer setup output.
    #[allow(clippy::too_many_arguments)]
    pub fn from_artifact_bytes(
        package: CompiledPackage,
        entry_info: EntryInfo,
        config: CircuitConfigArgs,
        k: u32,
        pubs_indices: Vec<usize>,
        params_bytes: &[u8],
        pk_bytes: &[u8],
        vk_bytes: &[u8],
    ) -> Result<Self> {
        let mut params =
            ParamsKZG::<Bn256>::read_custom(&mut Cursor::new(params_bytes), SerdeFormat::RawBytes)?;
        if k < params.k() {
            params.downsize(k);
        }

        let (circuit, _circuit_guard) =
            build_empty_circuit(&package, entry_info.clone(), config.clone(), &pubs_indices)?;

        let pk = pk_read::<G1Affine, _, _>(
            &mut Cursor::new(pk_bytes),
            SerdeFormat::RawBytes,
            k,
            circuit.as_ref(),
            false,
        )?;
        let vk = vk_read::<G1Affine, _, _>(
            &mut Cursor::new(vk_bytes),
            SerdeFormat::RawBytes,
            k,
            circuit.as_ref(),
            false,
        )?;

        Ok(Self::from_parts(
            package,
            entry_info,
            config,
            params,
            pk,
            vk,
            k,
            pubs_indices,
        ))
    }

    pub fn params_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.params
            .write_custom(&mut bytes, SerdeFormat::RawBytes)?;
        Ok(bytes)
    }

    pub fn pk_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.pk.write(&mut bytes, SerdeFormat::RawBytes)?;
        Ok(bytes)
    }

    pub fn vk_bytes(&self) -> Vec<u8> {
        self.vk.to_bytes(SerdeFormat::RawBytes)
    }
}
