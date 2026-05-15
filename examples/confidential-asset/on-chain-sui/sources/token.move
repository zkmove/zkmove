module confidential_asset_sui::token;

use halo2_common::serialized_public_inputs::PublicInputs;
use verifier_api::native_verifier::{Self, SerializedCircuit, SerializedVK};
use verifier_api::serialized_params_store::SerializedParams;

public struct MintCap has key, store {
    id: UID,
}

public struct Store has key, store {
    id: UID,
    encrypted_value: u256,
}

const EInvalidProof: u64 = 1;
const EZeroAmount: u64 = 2;

const ENCRYPTED_ZERO: u256 = 1057098720325748203296752469094320832019875087793557438351763779692404987367u256;

public fun new_mint_cap(ctx: &mut TxContext): MintCap {
    MintCap { id: object::new(ctx) }
}

public fun register(ctx: &mut TxContext): Store {
    Store {
        id: object::new(ctx),
        encrypted_value: ENCRYPTED_ZERO,
    }
}

public fun mint(
    _cap: &MintCap,
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    circuit: &SerializedCircuit,
    encrypted_amount: u256,
    public_inputs: PublicInputs,
    proof: vector<u8>,
) {
    assert!(encrypted_amount > 0, EZeroAmount);
    assert!(
        native_verifier::verify_proof(
            params,
            vk,
            circuit,
            public_inputs,
            proof,
            native_verifier::kzg_gwc(),
            false,
            0,
        ),
        EInvalidProof,
    );

    store.encrypted_value = encrypted_amount;
}

public fun balance_of(store: &Store): u256 {
    store.encrypted_value
}

public fun destroy_mint_cap(cap: MintCap) {
    let MintCap { id } = cap;
    object::delete(id)
}

public fun destroy_store(store: Store) {
    let Store { id, encrypted_value: _ } = store;
    object::delete(id)
}
