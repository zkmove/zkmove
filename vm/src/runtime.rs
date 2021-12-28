// Copyright (c) zkMove Authors

use crate::move_circuit::FastMoveCircuit;
use error::{RuntimeError, StatusCode, VmResult};
use halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey};
use halo2::poly::commitment::Params;
use halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2::{dev::MockProver, pasta::EqAffine, pasta::Fp};
use logger::prelude::*;
use move_binary_format::CompiledModule;
use movelang::argument::ScriptArguments;
use movelang::loader::MoveLoader;

pub struct Runtime {
    loader: MoveLoader,
}

impl Runtime {
    pub fn new() -> Self {
        Runtime {
            loader: MoveLoader::new(),
        }
    }

    pub fn loader(&self) -> &MoveLoader {
        &self.loader
    }

    pub fn mock_prove_script(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        k: u32,
    ) -> VmResult<()> {
        let circuit = FastMoveCircuit::new(script, modules, args, self.loader());

        let public_inputs = vec![Fp::zero()];
        let prover = MockProver::<Fp>::run(k, &circuit, vec![public_inputs]).map_err(|e| {
            debug!("Prover Error: {:?}", e);
            RuntimeError::new(StatusCode::SynthesisError)
        })?;
        assert_eq!(prover.verify(), Ok(()));
        Ok(())
    }

    pub fn setup_script(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        params: &Params<EqAffine>,
    ) -> VmResult<ProvingKey<EqAffine>> {
        let circuit = FastMoveCircuit::new(script, modules, None, self.loader());
        debug!("Generate vk");
        let vk = keygen_vk(params, &circuit).map_err(|_| {
            RuntimeError::new(StatusCode::SynthesisError)
                .with_message("keygen_vk should not fail".to_string())
        })?;
        debug!("Generate pk");
        let pk = keygen_pk(params, vk, &circuit).map_err(|_| {
            RuntimeError::new(StatusCode::SynthesisError)
                .with_message("keygen_pk should not fail".to_string())
        })?;
        Ok(pk)
    }

    pub fn prove_script(
        &self,
        script: Vec<u8>,
        modules: Vec<CompiledModule>,
        args: Option<ScriptArguments>,
        params: &Params<EqAffine>,
        pk: ProvingKey<EqAffine>,
    ) -> VmResult<()> {
        let circuit = FastMoveCircuit::new(script, modules, args, self.loader());

        let public_inputs = vec![Fp::zero()];
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        // Create a proof
        create_proof(
            params,
            &pk,
            &[circuit],
            &[&[public_inputs.as_slice()]],
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();

        let msm = params.empty_msm();
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let guard = verify_proof(
            params,
            pk.get_vk(),
            msm,
            &[&[public_inputs.as_slice()]],
            &mut transcript,
        )
        .unwrap();
        let msm = guard.clone().use_challenges();
        assert!(msm.eval());
        Ok(())
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}
