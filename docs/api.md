Rust API

zkmove cli

```rust
/// commandline, not api
pub fn setup(params_path, package_path, witness: Option<Footprints>, circuit_name) 
              -> (CompiledPackage, pubs_indices/*entry_info?*/, params, pk, vk)
{
    // load package
    let rooted_path = SourcePackageLayout::try_find_root(&path.canonicalize()?)?;
    let build_path = rooted_path
        .join(CompiledPackageLayout::Root.path())
        .join(TEST_PACKAGE_NAME);
    let package =
        OnDiskCompiledPackage::from_path(build_path.as_path())?.into_compiled_package()?;

    // load traces
    if witness.is_some() {
        let args = traces.args().expect("Args not found");
        let pubs_indices: Vec<usize> = Vec::from_iter(0..args.len());
        let public_inputs = PublicInputs::new(&args, pubs_indices.as_slice());
        let circuit_config_args = CircuitConfigArgs::new(Some(TEST_CIRCUIT_ROWS/*read from toml*/), TEST_HASH_ROWS);
    
        let circuit = Rc::new(VmCircuit::<Fr>::new(
            &package,
            &traces,
            &pubs_indices,
            circuit_config_args.clone(),
        ));
        let _circuit_guard = CircuitGuard::new(circuit.clone());
        
    } else {
        debug!("Generate keys with custom number of rows");
        //let entry = traces.entry().expect("Entry not found");
        let entry = get_entry_info_from_move_toml();
        let circuit = Rc::new(VmCircuit::<Fr>::new_with_empty_state(
                &package,
                entry,
                &pubs_indices,
                circuit_config_args.clone(),
            ));
            let _circuit_guard = CircuitGuard::new(test_circuit.clone());
    }
    
    let mut params_file = std::fs::File::open(&self.params_path)?;
    let mut params = ParamsKZG::<Bn256>::read(&mut params_file)?;
    let k = best_k(&circuit);
    info!("Optimal k = {}", k);
    if k < params.k() {
        params.downsize(k);
    }
    let (vk, pk) = setup_circuit(&*circuit, &params).expect("setup should not fail")

}

```

1.zkmove api

```rust

pub fn dry_run(
    package: &CompiledPackage,
    module_id: &ModuleId,
    function_name: &str,
    args: &[TransactionArgument],
)->xxx //state 不落盘如何处理？

/// Generate a proof for the given witness against the circuit derived from `package`.
///
/// `params` may be downsized in place to the optimal `k`.
pub fn prove(
    package: &CompiledPackage,
    //? entry_info: EntryInfo,
    module_id: &ModuleId,
    function_name: &str,
    args: &[TransactionArgument],
    
    config: CircuitConfigArgs, //----> entry_info??
    params: &mut ParamsKZG<Bn256>,
    pubs_indices: &[usize],
    variant: KZGVariant,
) -> Result<ProveOutput> {

   //把dry_run逻辑加进来
}

/// Verify a proof locally by rebuilding the verifying key from the empty-state circuit.
///
/// `params` may be downsized in place to `k`.
pub fn verify(
    package: &CompiledPackage,
    entry_info: EntryInfo, //?
    config: CircuitConfigArgs,
    params: &mut ParamsKZG<Bn256>,
    k: u32,
    pubs_indices: &[usize],
    variant: KZGVariant,
    proof: &[u8],
    pubs_bytes: &[u8],
) -> Result<()>;

/// Compute `poseidon_hash(value, nonce)` returning the result as a `U256`.
pub fn poseidon_hash(value: u128, nonce: u128) -> Result<U256>;
```

2.aptos verifier api

```rust
[dependencies]
aptos-verifier-api = { git = "https://github.com/zkmove/halo2-verifier.move", branch = "main" }
```

```rust
use aptos_verifier_api::native_verifier::{
    build_publish_circuit_native_transaction_payload,
    build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload,
    build_verify_proof_native_transaction_payload,
};
use aptos_verifier_api::verifier::{
    build_publish_circuit_transaction_payload, build_publish_params_transaction_payload,
    build_verify_proof_transaction_payload,
};
```

3.sui verifier api

```rust
[dependencies]
sui-verifier-api = { git = "https://github.com/zkmove/halo2-verifier.move", branch = "main" }
```

```rust
use sui_verifier_api::native_verifier::{
    build_publish_params_native_transaction_payload, build_publish_vk_native_transaction_payload,
    build_verify_proof_native_transaction_payload,
};
```