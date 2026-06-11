module confidential_asset_sui::token;

use sui::bcs;
use verifier_api::native_verifier::{Self, SerializedVK};
use verifier_api::serialized_public_inputs;
use verifier_api::serialized_params_store::SerializedParams;

public struct MintCap has key, store {
    id: UID,
}

public struct Token has drop, store {
    encrypted_value: u256,
}

public struct Store has key, store {
    id: UID,
    token: Token,
    inbox: vector<Token>,
}

const EInvalidProof: u64 = 1;
const EZeroAmount: u64 = 2;
const EIndexOutOfBounds: u64 = 3;
const EInvalidInput: u64 = 4;

const ENCRYPTED_ZERO: u256 = 1057098720325748203296752469094320832019875087793557438351763779692404987367u256;

public fun new_mint_cap(ctx: &mut TxContext): MintCap {
    MintCap { id: object::new(ctx) }
}

entry fun publish_mint_cap(ctx: &mut TxContext) {
    transfer::transfer(new_mint_cap(ctx), ctx.sender())
}

public fun register(ctx: &mut TxContext): Store {
    Store {
        id: object::new(ctx),
        token: Token { encrypted_value: ENCRYPTED_ZERO },
        inbox: vector[],
    }
}

entry fun register_to_sender(ctx: &mut TxContext) {
    transfer::transfer(register(ctx), ctx.sender())
}

public fun mint(
    _cap: &MintCap,
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_amount: u256,
    proof: vector<u8>,
) {
    assert!(encrypted_amount > 0, EZeroAmount);
    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, encrypted_amount);
    verify(params, vk, public_inputs, proof);

    send_token(Token { encrypted_value: encrypted_amount }, store);
}

entry fun mint_entry(
    cap: &MintCap,
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_amount: u256,
    proof: vector<u8>,
) {
    mint(
        cap,
        store,
        params,
        vk,
        encrypted_amount,
        proof,
    )
}

public fun transfer(
    from: &mut Store,
    to: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_amount: u256,
    encrypted_remaining: u256,
    proof: vector<u8>,
) {
    let token = withdraw(
        from,
        params,
        vk,
        encrypted_amount,
        encrypted_remaining,
        proof,
    );
    send_token(token, to);
}

entry fun transfer_entry(
    from: &mut Store,
    to: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_amount: u256,
    encrypted_remaining: u256,
    proof: vector<u8>,
) {
    transfer(from, to, params, vk, encrypted_amount, encrypted_remaining, proof)
}

public fun claim_inbox_by_index(
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    index: u64,
    encrypted_new_balance: u256,
    proof: vector<u8>,
) {
    assert!(index < store.inbox.length(), EIndexOutOfBounds);

    let token = store.inbox.remove(index);
    let encrypted_amount = token.encrypted_value;
    let encrypted_balance = store.token.encrypted_value;

    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, encrypted_balance);
    push_u256(&mut public_inputs, encrypted_amount);
    push_u256(&mut public_inputs, encrypted_new_balance);
    verify(params, vk, public_inputs, proof);

    store.token.encrypted_value = encrypted_new_balance;
}

entry fun claim_inbox_by_index_entry(
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    index: u64,
    encrypted_new_balance: u256,
    proof: vector<u8>,
) {
    claim_inbox_by_index(store, params, vk, index, encrypted_new_balance, proof)
}

public fun burn(
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    proof: vector<u8>,
) {
    let encrypted_balance = store.token.encrypted_value;

    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, encrypted_balance);
    verify(params, vk, public_inputs, proof);

    store.token.encrypted_value = ENCRYPTED_ZERO;
}

entry fun burn_entry(
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    proof: vector<u8>,
) {
    burn(store, params, vk, proof)
}

public fun balance_of(store: &Store): u256 {
    store.token.encrypted_value
}

public fun inbox_length(store: &Store): u64 {
    store.inbox.length()
}

public fun inbox_token_value(store: &Store, index: u64): u256 {
    assert!(index < store.inbox.length(), EIndexOutOfBounds);
    store.inbox[index].encrypted_value
}

public fun token_value(token: &Token): u256 {
    token.encrypted_value
}

public fun range_check(
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_value: u256,
    min: u128,
    max: u128,
    proof: vector<u8>,
) {
    assert!(min <= max, EInvalidInput);
    let mut public_inputs = empty_vm_public_inputs();
    push_u128(&mut public_inputs, min);
    push_u128(&mut public_inputs, max);
    push_u256(&mut public_inputs, encrypted_value);
    verify(params, vk, public_inputs, proof);
}

entry fun range_check_entry(
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_value: u256,
    min: u128,
    max: u128,
    proof: vector<u8>,
) {
    range_check(params, vk, encrypted_value, min, max, proof)
}

public fun destroy_mint_cap(cap: MintCap) {
    let MintCap { id } = cap;
    object::delete(id)
}

public fun destroy_store(store: Store) {
    let Store { id, token: _, inbox: _ } = store;
    object::delete(id)
}

fun withdraw(
    store: &mut Store,
    params: &SerializedParams,
    vk: &SerializedVK,
    encrypted_amount: u256,
    encrypted_remaining: u256,
    proof: vector<u8>,
): Token {
    let encrypted_balance = store.token.encrypted_value;

    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, encrypted_remaining);
    push_u256(&mut public_inputs, encrypted_amount);
    push_u256(&mut public_inputs, encrypted_balance);
    verify(params, vk, public_inputs, proof);

    store.token.encrypted_value = encrypted_remaining;
    Token { encrypted_value: encrypted_amount }
}

fun send_token(token: Token, recipient: &mut Store) {
    recipient.inbox.push_back(token)
}

fun verify(
    params: &SerializedParams,
    vk: &SerializedVK,
    public_inputs_bytes: vector<vector<vector<u8>>>,
    proof: vector<u8>,
) {
    assert!(
        native_verifier::verify_proof(
            params,
            vk,
            serialized_public_inputs::from_bytes(public_inputs_bytes),
            proof,
            native_verifier::kzg_gwc(),
            false,
            0,
        ),
        EInvalidProof,
    );
}

fun empty_vm_public_inputs(): vector<vector<vector<u8>>> {
    vector[vector[], vector[], vector[], vector[]]
}

fun push_u128(public_inputs: &mut vector<vector<vector<u8>>>, value: u128) {
    push_vm_row(public_inputs, 0, value, 0)
}

fun push_u256(public_inputs: &mut vector<vector<vector<u8>>>, value: u256) {
    let lo_mask = (1u256 << 128) - 1;
    let lo = ((value & lo_mask) as u128);
    let hi = ((value >> 128) as u128);
    push_vm_row(public_inputs, 0, lo, hi)
}

fun push_vm_row(
    public_inputs: &mut vector<vector<vector<u8>>>,
    sub_index: u128,
    word_lo: u128,
    word_hi: u128,
) {
    public_inputs[0].push_back(scalar_u128(sub_index));
    public_inputs[1].push_back(scalar_u128(0));
    public_inputs[2].push_back(scalar_u128(word_lo));
    public_inputs[3].push_back(scalar_u128(word_hi));
}

fun scalar_u128(value: u128): vector<u8> {
    let mut bytes = bcs::to_bytes(&value);
    let mut i = 0;
    while (i < 16u64) {
        bytes.push_back(0);
        i = i + 1;
    };
    bytes
}

#[test_only]
public fun encrypt_public_inputs_for_test(encrypted_value: u256): vector<vector<vector<u8>>> {
    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, encrypted_value);
    public_inputs
}

#[test_only]
public fun sum_public_inputs_for_test(
    first: u256,
    second: u256,
    third: u256,
): vector<vector<vector<u8>>> {
    let mut public_inputs = empty_vm_public_inputs();
    push_u256(&mut public_inputs, first);
    push_u256(&mut public_inputs, second);
    push_u256(&mut public_inputs, third);
    public_inputs
}

#[test_only]
public fun range_public_inputs_for_test(
    min: u128,
    max: u128,
    encrypted_value: u256,
): vector<vector<vector<u8>>> {
    let mut public_inputs = empty_vm_public_inputs();
    push_u128(&mut public_inputs, min);
    push_u128(&mut public_inputs, max);
    push_u256(&mut public_inputs, encrypted_value);
    public_inputs
}
