/// Module: confidential_asset::token
module confidential_asset::token {
    use std::signer;
    use std::vector;

    struct Token has store, key, drop {
        value: u64
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

    /// Module initializer
    fun init_module(deployer: &signer) {
        move_to(deployer, MintCap {});
    }

    /// Register: create Store with zero Token
    public entry fun register(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<Store>(addr), EALREADY_HAS_STORE);
        move_to(account, Store { token: Token { value: 0 } });
        move_to(account, Inbox { items: vector::empty() });
    }

    /// Mint: increase Token.value in receiver's Store
    public entry fun mint(admin: &signer, to: address, amount: u64) acquires Store {
        assert!(amount > 0, EZERO_AMOUNT);
        assert!(exists<MintCap>(signer::address_of(admin)), ENO_MINT_CAPABILITY);
        assert!(exists<Store>(to), ENO_STORE);

        let store = borrow_global_mut<Store>(to);
        store.token.value = store.token.value + amount;
    }

    /// Transfer: transfer Token from own Store to another's Store
    public entry fun transfer(from: &signer, to: address, amount: u64) acquires Store, Inbox {
        let token = withdraw(from, amount);
        send_token(token, to);
    }

    /// Withdraw: extract a new Token resource from own Store
    public fun withdraw(account: &signer, amount: u64): Token acquires Store {
        assert!(amount > 0, EZERO_AMOUNT);
        let addr = signer::address_of(account);
        let store = borrow_global_mut<Store>(addr);
        assert!(store.token.value >= amount, EINSUFFICIENT_BALANCE);
        store.token.value = store.token.value - amount;

        Token { value: amount }
    }

    /// Send a standalone Token to anyone
    fun send_token(token: Token, recipient: address) acquires Inbox {
        assert!(exists<Inbox>(recipient), ENO_STORE);
        let inbox = borrow_global_mut<Inbox>(recipient);
        vector::push_back(&mut inbox.items, token);
    }

    /// Deposit: merge an external Token back into Store
    public fun deposit(account: &signer, token: Token) acquires Store {
        let addr = signer::address_of(account);
        let store = borrow_global_mut<Store>(addr);
        let Token { value } = token;
        store.token.value = store.token.value + value;
    }

    /// Claim inbox: move all Tokens from Inbox into Store
    public entry fun claim_inbox(account: &signer) acquires Store, Inbox {
        let addr = signer::address_of(account);
        assert!(exists<Inbox>(addr), ENO_STORE);

        let inbox = borrow_global_mut<Inbox>(addr);
        let store = borrow_global_mut<Store>(addr);

        while (!vector::is_empty(&inbox.items)) {
            let token = vector::pop_back(&mut inbox.items);
            store.token.value = store.token.value + token.value;
            let Token { value: _ } = token;
        }
    }

    // View functions
    public fun balance_of(owner: address): u64 acquires Store {
        if (exists<Store>(owner)) {
            borrow_global<Store>(owner).token.value
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
        t.value
    }
}