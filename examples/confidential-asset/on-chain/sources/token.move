/// Module: confidential_asset::token
module confidential_asset::token {
    use std::signer;
    use std::vector;
    use aptos_std::bn254_algebra::Fr;
    use verifier_api::verifier;
    use halo2_common::public_inputs;

    struct Token has store, key, drop {
        encrypted_value: u256
    }

    struct Store has key {
        token: Token
    }

    struct Inbox has key {
        items: vector<Token>
    }

    struct MintCap has key {}

    // Error codes
    const EINSUFFICIENT_BALANCE: u64 = 1;
    const ENO_MINT_CAPABILITY:   u64 = 2;
    const EALREADY_HAS_STORE:    u64 = 3;
    const ENO_STORE:             u64 = 4;
    const EZERO_AMOUNT:          u64 = 5;
    const ENO_TOKEN:             u64 = 6;
    const ENO_INBOX:             u64 = 7;
    const EINDEX_OUT_OF_BOUNDS:  u64 = 8;
    const EINVALID_PROOF: u64 = 9;
    const EINVALID_INPUT: u64 = 10;

    /// kzg variant
    const KZG_GWC:     u8 = 1;
    const KZG_SHPLONK: u8 = 0;

    /// Pre-computed encryption of zero
    const ENCRYPTED_ZERO: u256 = 1057098720325748203296752469094320832019875087793557438351763779692404987367u256;
    const NONCE_ZERO: u128 = 42u128;
    
    /// Module initializer
    fun init_module(deployer: &signer) {
        move_to(deployer, MintCap {});
    }

    #[test_only]
    public fun init_for_test(deployer: &signer) {
        move_to(deployer, MintCap {});
    }

    /// Register: create Store with zero Token
    public entry fun register(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<Store>(addr), EALREADY_HAS_STORE);
        move_to(account, Store { token: Token { encrypted_value: ENCRYPTED_ZERO } });
        move_to(account, Inbox { items: vector::empty() });
    }

    /// Mint token and send it to receiver
    /// proof: the proof to prove encrypt(amount, encrypted_amount, nonce) is valid
    public entry fun mint(admin: &signer, to: address, amount: u128, encrypted_amount: u256, proof: vector<u8>) {
        assert!(amount > 0, EZERO_AMOUNT);
        assert!(exists<MintCap>(signer::address_of(admin)), ENO_MINT_CAPABILITY);
        assert!(exists<Store>(to), ENO_STORE);

        // verify "hash(amount) == encrypted_amount"
        let pi = public_inputs::empty<Fr>(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_u256(&mut pi, encrypted_amount);
        assert!(verifier::mock_verify_proof(@param_address, @circuit_encrypt_address, pi, proof, KZG_GWC), EINVALID_PROOF);

        let token = Token { encrypted_value: encrypted_amount };
        send_token(token, to);
    }

    /// Transfer: transfer Token from own Store to another's Store
    public entry fun transfer(from: &signer, to: address, encrypted_amount: u256, encrypted_remaining: u256, proof: vector<u8>) acquires Store, Inbox {
        let token = withdraw(from, encrypted_amount, encrypted_remaining, proof);
        send_token(token, to);
    }

    /// Withdraw: extract a new Token resource from own Store
    /// proof: the proof to prove check_sum(remaining, amount, balance, encrypted_remaining, encrypted_amount, encrypted_balance, nonce_remaining, nonce_amount, nonce_balance) is valid
    /// Note: amount and nonce_amount are private inputs of circuit_check_sum, they should be sent to the recipient off-chain
    fun withdraw(account: &signer, encrypted_amount: u256, encrypted_remaining: u256, proof: vector<u8>): Token acquires Store {
        let addr = signer::address_of(account);
        let store = borrow_global_mut<Store>(addr);
        let encrypted_balance = store.token.encrypted_value;

        // verify "balance - amount == remaining"
        let pi = public_inputs::empty<Fr>(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_u256(&mut pi, encrypted_remaining);
        public_inputs::push_u256(&mut pi, encrypted_amount);
        public_inputs::push_u256(&mut pi, encrypted_balance);
        assert!(verifier::mock_verify_proof(@param_address, @circuit_check_sum_address, pi, proof, KZG_GWC), EINVALID_PROOF);

        store.token.encrypted_value = encrypted_remaining;
        Token { encrypted_value: encrypted_amount }
    }

    /// Send a standalone Token to anyone
    fun send_token(token: Token, recipient: address) acquires Inbox {
        assert!(exists<Inbox>(recipient), ENO_INBOX);
        let inbox = borrow_global_mut<Inbox>(recipient);
        vector::push_back(&mut inbox.items, token);
    }

    /// Claim inbox item by index
    /// proof: the proof to prove check_sum(balance, amount, new_balance, encrypted_balance, encrypted_amount, encrypted_new_balance, nonce_balance, nonce_amount, nonce_new_balance) is valid
    /// Note: amount and nonce_amount are received off-chain when the token is sent by the sender
    public entry fun claim_inbox_by_index(account: &signer, index: u64, encrypted_new_balance: u256, proof: vector<u8>) acquires Store, Inbox {
        let addr = signer::address_of(account);
        assert!(exists<Inbox>(addr), ENO_INBOX);
        assert!(exists<Store>(addr), ENO_STORE);

        let inbox = borrow_global_mut<Inbox>(addr);
        let len = vector::length(&inbox.items);
        assert!(index < len, EINDEX_OUT_OF_BOUNDS);

        let token = vector::remove(&mut inbox.items, index);
        let encrypted_amount = token.encrypted_value;

        let store = borrow_global_mut<Store>(addr);
        let encrypted_balance = store.token.encrypted_value;

        // verify "balance + amount == new_balance"
        let pi = public_inputs::empty<Fr>(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_u256(&mut pi, encrypted_balance);
        public_inputs::push_u256(&mut pi, encrypted_amount);
        public_inputs::push_u256(&mut pi, encrypted_new_balance);
        assert!(verifier::mock_verify_proof(@param_address, @circuit_check_sum_address, pi, proof, KZG_GWC), EINVALID_PROOF);

        store.token.encrypted_value = encrypted_new_balance;
        let Token { encrypted_value: _ } = token;
    }

    /// Burn token in own Store
    /// proof: the proof to prove encrypt(balance, encrypted_balance, nonce) is valid
    public entry fun burn(account: &signer, proof: vector<u8>) acquires Store {
        let addr = signer::address_of(account);
        assert!(exists<Store>(addr), ENO_STORE);
        let store = borrow_global_mut<Store>(addr);
        let encrypted_balance = store.token.encrypted_value;

        // verify "hash(balance) == encrypted_balance"
        let pi = public_inputs::empty<Fr>(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_u256(&mut pi, encrypted_balance);
        assert!(verifier::mock_verify_proof(@param_address, @circuit_encrypt_address, pi, proof, KZG_GWC), EINVALID_PROOF);

        store.token.encrypted_value = ENCRYPTED_ZERO;
    }

    // View functions
    public fun balance_of(owner: address): u256 acquires Store {
        if (exists<Store>(owner)) {
            borrow_global<Store>(owner).token.encrypted_value
        } else {
            0
        }
    }

    public fun inbox_length(owner: address): u64 acquires Inbox {
        if (exists<Inbox>(owner)) {
            vector::length(&borrow_global<Inbox>(owner).items)
        } else {
            0
        }
    }

    public fun token_value(t: &Token): u256 {
        t.encrypted_value
    }

    public fun range_check(encrypted_value: u256, min: u128, max: u128, proof: vector<u8>) {
        assert!(min <= max, EINVALID_INPUT);
        // verify "encrypted_value is an encryption of a value in range [min, max]"
        let pi = public_inputs::empty<Fr>(public_inputs::get_vm_public_inputs_column_count());
        public_inputs::push_u128(&mut pi, min);
        public_inputs::push_u128(&mut pi, max);
        public_inputs::push_u256(&mut pi, encrypted_value);
        assert!(
            verifier::mock_verify_proof(@param_address, @circuit_range_check_address, pi, proof, KZG_GWC),
            EINVALID_PROOF
        );
    }
}