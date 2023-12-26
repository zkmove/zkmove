use super::{TestCircuit1, TestCircuit2};
use anyhow::Result;
use ark_std::test_rng;
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs;
use halo2_proofs::poly::kzg::commitment::ParamsKZG; //guangyuz
use halo2_proofs::{halo2curves::bn256::Bn256, poly::commitment::Params};
use snark_verifier_sdk::{
    gen_evm_proof_shplonk, gen_pk, gen_snark_shplonk, AggregationCircuit, CircuitExt,
};
use std::path::Path;

#[test]
fn test_app_circuit_aggregation() -> Result<()> {
    logger::init_for_test();
    std::env::set_var("VERIFY_CONFIG", "./configs/app_circuit_aggregation.config");
    let param_path = Path::new("./params/kzg_bn254_21.srs");
    let mut param_file = std::fs::File::open(param_path)?;
    let params_outer = ParamsKZG::<Bn256>::read(&mut param_file)?;
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(8);
        params
    };

    let mut rng = test_rng();
    // Proof for circuit 1
    let circuit_1 = TestCircuit1::rand(&mut rng);
    let pk_inner_1 = gen_pk(&params_inner, &circuit_1, None);
    let snarks_1 = gen_snark_shplonk(
        &params_inner,
        &pk_inner_1,
        circuit_1.clone(),
        &mut rng,
        Some(Path::new("./data/app_circuit_1.snark")),
    );
    println!("finished snark generation for circuit 1");

    // Proof for circuit 2
    let circuit_2 = TestCircuit2::rand(&mut rng);
    let pk_inner_2 = gen_pk(&params_inner, &circuit_2, None);
    let snarks_2 = gen_snark_shplonk(
        &params_inner,
        &pk_inner_2,
        circuit_1.clone(),
        &mut rng,
        Some(Path::new("data/app_circuit_2.snark")),
    );
    println!("finished snark generation for circuit 2");

    // aggregation circuit
    let snarks = vec![snarks_1, snarks_2];
    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
    let pk_outer = gen_pk(&params_outer, &agg_circuit, None);
    println!("finished outer pk generation");
    let aggregation_time = start_timer!(|| "start generation...");
    let instances = agg_circuit.instances();
    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances.clone(),
        &mut rng,
    );
    println!("finished aggregation generation");
    end_timer!(aggregation_time);
    println!("aggregated proof size {} bytes", proof.len());
    // TODO: verify on move

    Ok(())
}
