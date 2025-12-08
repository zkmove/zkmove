/// Module: confidential_asset::token
module confidential_asset::token {
    use std::signer;
    use std::vector;
    use std::zkhash;

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

    /// Module initializer
    fun init_module(deployer: &signer) {
        move_to(deployer, MintCap {});
    }

    /// Register: create Store with zero Token
    public entry fun register(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<Store>(addr), EALREADY_HAS_STORE);
        move_to(account, Store { token: Token { encrypted_value: 0 } });
        move_to(account, Inbox { items: vector::empty() });
    }

    /// Mint token and send it to receiver
    public entry fun mint(admin: &signer, to: address, encrypted_amount: u256) acquires Store {
        assert!(amount > 0, EZERO_AMOUNT);
        assert!(exists<MintCap>(signer::address_of(admin)), ENO_MINT_CAPABILITY);
        assert!(exists<Store>(to), ENO_STORE);

        let token = Token { encrypted_value: encrypted_amount };
        send_token(token, to);
    }

    /// Transfer: transfer Token from own Store to another's Store
    public entry fun transfer(from: &signer, to: address, encrypted_amount: u256, encrypted_remaining: u256, proof: vector<u8>) acquires Store, Inbox {
        let encrypted_balance = balance_of(signer::address_of(from));
        let token = withdraw(from, encrypted_amount, proof);
        send_token(token, to);
    }

    /// Withdraw: extract a new Token resource from own Store
    /// proof: to prove check_sum(remaining, amount, balance, encrypted_remaining, encrypted_amount, encrypted_balance) is valid
    fun withdraw(account: &signer, encrypted_amount: u256, encrypted_remaining: u256, proof: vector<u8>): Token acquires Store {
        let addr = signer::address_of(account);
        let store = borrow_global_mut<Store>(addr);
        let encrypted_balance = store.token.encrypted_value;

        // verify "balance - amount == remaining"
        let pi = PublicInputs::new(encrypted_remaining, encrypted_amount, encrypted_balance);
        assert!(verifier_api::verify_proof(@param_address, @circuit_address, pi, proof, kzg_variant) == true, EINVALID_PROOF);

        store.token.encrypted_value = encrypted_remaining;
        Token { encrypted_value: encrypted_amount }
    }

    /// Send a standalone Token to anyone
    fun send_token(token: Token, recipient: address) acquires Inbox {
        assert!(exists<Inbox>(recipient), ENO_STORE);
        let inbox = borrow_global_mut<Inbox>(recipient);
        vector::push_back(&mut inbox.items, token);
    }

    /// Claim inbox item by index
    public entry fun claim_inbox_by_index(account: &signer, index: u64, encrypted_amount: u256, encrypted_new_balance: u256, proof: vector<u8>) acquires Store, Inbox {
        let addr = signer::address_of(account);
        assert!(exists<Inbox>(addr), ENO_STORE);
        assert!(exists<Store>(addr), ENO_STORE);

        let inbox = borrow_global_mut<Inbox>(addr);
        let len = vector::length(&inbox.items);
        assert!(index < len, EINDEX_OUT_OF_BOUNDS);

        let token = vector::remove(&mut inbox.items, index);

        let store = borrow_global_mut<Store>(addr);
        let encrypted_balance = store.token.encrypted_value;

        // verify "balance + amount == new_balance"
        let pi = PublicInputs::new(encrypted_balance, encrypted_amount, encrypted_new_balance);
        assert!(verifier_api::verify_proof(@param_address, @circuit_address, pi, proof, kzg_variant) == true, EINVALID_PROOF);

        let Token { value: _ } = token;
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

    public fun token_value(t: &Token): u64 {
        t.encrypted_value
    }
}