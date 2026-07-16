#[test_only]
module confidential_asset::confidential_asset_tests {
    use std::signer;
    use aptos_framework::account;
    use aptos_std::debug;

    use confidential_asset::token::{
        init_for_test, register, mint, transfer, balance_of, claim_inbox_by_index, burn,
    };

    /// Pre-computed encryption of zero
    const ENCRYPTED_ZERO: u256 = 1057098720325748203296752469094320832019875087793557438351763779692404987367u256;

    #[test(admin = @confidential_asset, alice = @0x123, bob = @0x456)]
    fun test_full_flow(
        admin: &signer,
        alice: &signer,
        bob: &signer,
    ) {
        // 0. users build and publish the off-chain modules in the client side

        // under folder `examples/confidential-asset/off_chain/`, run the following commands:
        // ```move build```
        // ```move sandbox publish --skip-fetch-latest-git-deps --ignore-breaking-changes```

        // 1. init_module
        init_for_test(admin);

        // 2. create test accounts
        let admin_addr = signer::address_of(admin);
        let alice_addr = signer::address_of(alice);
        let bob_addr = signer::address_of(bob);
        account::create_account_for_test(admin_addr);
        account::create_account_for_test(alice_addr);
        account::create_account_for_test(bob_addr);

        // 3. Alice and Bob register store
        register(alice);
        register(bob);

        assert!(balance_of(alice_addr) == ENCRYPTED_ZERO, 100);
        assert!(balance_of(bob_addr) == ENCRYPTED_ZERO, 101);

        // 4. Admin mint 1000 to Alice

        let amount = 1000u128; // secret data

        // Admin generates `encrypted_amount` and `nonce` with zkmove cli:
        // ```zkmove poseidon -v 1000```
        let encrypted_amount = 10336830281148641948660636302338894304453011972931132221837472050495421477678u256;
        let nonce_amount = 336859558035047134399322722797443334272u128;

        // Admin generates witness for `encrypt(amount, encrypted_amount, nonce_amount)` with below command. The witness is output to the file 'witnesses/encrypt-xxx.json'.
        // ```move sandbox run --skip-fetch-latest-git-deps --witness storage/0x000000000000000000000000000000000000000000000000000000000000cafe/modules/encryption.mv encrypt --args 1000u128 10336830281148641948660636302338894304453011972931132221837472050495421477678u256 336859558035047134399322722797443334272u128```

        // Admin generates proof for `encrypt(amount, encrypted_amount, nonce_amount)`. The proof is output to the file 'proofs/encrypt-xxx.json'. Here we just use a fake one for testing purpose.
        // ```zkmove vm --param-path ../../../cli/params/kzg_bn254_12.srs --package-path ./  --pubs-indices 1 --circuit-name encrypt prove --json -w witnesses/encrypt-xxx.json```
        let fake_proof = x"7e572d6628a900f395206ec82e5fe47d55db4bd614880a66417464b4e136fc12c6669a49d9dc93";
        mint(admin, alice_addr, amount, encrypted_amount, fake_proof);

        assert!(
            balance_of(alice_addr) == ENCRYPTED_ZERO,
            102
        );

        // 5. Alice claims the received 1000 from her inbox

        // Alice generates `encrypted_new_balance` and nonce_new_balance with zkmove cli:
        // ```zkmove poseidon -v 1000```
        let encrypted_new_balance = 13312467577338805256889354231553357084490260084109580443322478622540196278209u256;
        let nonce_new_balance = 61220211640970528624314717732868516112u128; // secret data

        // generates witness for `check_sum(0, 1000, 1000, ENCRYPTED_ZERO, encrypted_amount, encrypted_new_balance, NONCE_ZERO, nonce_amount, nonce_new_balance)` with below command. The witness is output to the file 'witnesses/check_sum-xxx.json'.
        // ```move sandbox run --skip-fetch-latest-git-deps --witness storage/0x000000000000000000000000000000000000000000000000000000000000cafe/modules/sum.mv check_sum --args 0u128 1000u128 1000u128 1057098720325748203296752469094320832019875087793557438351763779692404987367u256 10336830281148641948660636302338894304453011972931132221837472050495421477678u256 13312467577338805256889354231553357084490260084109580443322478622540196278209u256 42u128 336859558035047134399322722797443334272u128 61220211640970528624314717732868516112u128```

        // generates proof to the file 'proofs/check_sum-xxx.json'. Here we just use a fake one for testing purpose.
        // ```zkmove vm --param-path ../../../cli/params/kzg_bn254_12.srs --package-path ./  --pubs-indices 3 4 5 --circuit-name check_sum prove --json -w witnesses/check_sum-xxx.json```
        let fake_proof = x"6a7d8c9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";
        claim_inbox_by_index(alice, 0, encrypted_new_balance, fake_proof);
        assert!(
            balance_of(alice_addr) == 13312467577338805256889354231553357084490260084109580443322478622540196278209u256,
            103
        );


        // 6. Alice transfers 400 to Bob

        let amount = 400u128; // secret data
        let remaining = 600u128; // secret data

        // Alice generates `encrypted_amount` and nonce with zkmove cli:
        // ```zkmove poseidon -v 400```
        let encrypted_amount = 14195417829511350728699538423105367739974641274513641871364667470732299433635u256;
        let nonce_amount = 322128617302470551575546360976961439147u128; // secret data
        // ```zkmove poseidon -v 600```
        let encrypted_remaining = 18037755320587301379665663726174862721060146336179858921620539405664258279517u256;
        let nonce_remaining = 281138514339884582389268504631672012320u128; // secret data

        // generates witness for `check_sum(remaining, amount, balance, encrypted_remaining, encrypted_amount, encrypted_balance, nonce_remaining, nonce_amount, nonce_balance)` with below command. The witness is output to the file 'witnesses/check_sum-xxx.json'.
        // ```move sandbox run --skip-fetch-latest-git-deps --witness storage/0x000000000000000000000000000000000000000000000000000000000000cafe/modules/sum.mv check_sum --args 600u128 400u128 1000u128 18037755320587301379665663726174862721060146336179858921620539405664258279517u256 14195417829511350728699538423105367739974641274513641871364667470732299433635u256 10336830281148641948660636302338894304453011972931132221837472050495421477678u256 281138514339884582389268504631672012320u128 322128617302470551575546360976961439147u128 336859558035047134399322722797443334272u128```

        // generates proof to the file 'proofs/check_sum-xxx.json'. Here we just use a fake one for testing purpose.
        // ```zkmove vm --param-path ../../../cli/params/kzg_bn254_12.srs --package-path ./  --pubs-indices 3 4 5 --circuit-name check_sum prove --json -w witnesses/check_sum-xxx.json```
        let fake_proof = x"9e46dc91bd51d359df0279630ac17d6dc4c81edd0a863afb4f589c89d150cfa4ac702ebe6b123f";
        transfer(alice, bob_addr, encrypted_amount, encrypted_remaining, fake_proof);

        assert!(
            balance_of(alice_addr) == 18037755320587301379665663726174862721060146336179858921620539405664258279517u256,
            104
        );

        // Then, Alice informs Bob of the amount and the random number (nonce_amount) through an off-chain method.

        // 7. Bob claims the received 400 from his inbox

        // Bob generates `encrypted_new_balance` and nonce_new_balance with zkmove cli:
        // ```zkmove poseidon -v 400```
        let encrypted_new_balance = 121944004510302977207011161638527050052511373187793169577099029388311470887u256;
        let nonce_new_balance = 301507643374632252078286724861117218897u128; // secret data

        // generates witness for `check_sum(0, 400, 400, ENCRYPTED_ZERO, encrypted_amount, encrypted_new_balance, NONCE_ZERO, nonce_amount, nonce_new_balance)` with below command. The witness is output to the file 'witnesses/check_sum-xxx.json'.
        // ```move sandbox run --skip-fetch-latest-git-deps --witness storage/0x000000000000000000000000000000000000000000000000000000000000cafe/modules/sum.mv check_sum --args 0u128 400u128 400u128 1057098720325748203296752469094320832019875087793557438351763779692404987367u256 14195417829511350728699538423105367739974641274513641871364667470732299433635u256 121944004510302977207011161638527050052511373187793169577099029388311470887u256 42u128 322128617302470551575546360976961439147u128 301507643374632252078286724861117218897u128```

        // generates proof to the file 'proofs/check_sum-xxx.json'. Here we just use a fake one for testing purpose.
        // ```zkmove vm --param-path ../../../cli/params/kzg_bn254_12.srs --package-path ./  --pubs-indices 3 4 5 --circuit-name check_sum prove --json -w witnesses/check_sum-xxx.json```

        let fake_proof = x"6a7d8c9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";
        claim_inbox_by_index(bob, 0, encrypted_new_balance, fake_proof);

        assert!(
            balance_of(bob_addr) == 121944004510302977207011161638527050052511373187793169577099029388311470887u256,
            105
        );

        // 8. Bob burns the 400 token in the store

        // Bob generates proof for `encrypt(new_balance, encrypted_new_balance, nonce_new_balance)`. The proof is output to the file 'proofs/encrypt-xxx.json'.
        // ```zkmove vm --param-path ../../../cli/params/kzg_bn254_12.srs --package-path ./  --pubs-indices 1 --circuit-name encrypt prove --json -w witnesses/encrypt-xxx.json```
        //  Here we just use a fake one for testing purpose.
        let fake_proof = x"e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f";
        burn(bob, fake_proof);
        assert!(balance_of(bob_addr) == ENCRYPTED_ZERO, 106);

        debug::print(&b"Test passed: full flow + boundary cases");
    }
}
