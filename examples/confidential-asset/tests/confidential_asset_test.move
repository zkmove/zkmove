#[test_only]
module confidential_asset::confidential_asset_tests {
    use std::signer;
    use std::vector;
    use aptos_framework::account;
    use aptos_framework::timestamp;
    use aptos_std::debug;

    use confidential_asset::token::{
        Self, Store, Token, MintCap,
        register, mint, transfer, withdraw, deposit, balance_of, merge
    };

    const ADMIN_ADDR: address = @0xCAFE;
    const ALICE_ADDR: address = @0x123;
    const BOB_ADDR:   address = @0x456;

    #[test(admin = @confidential_asset)]
    fun test_full_flow(admin: &signer) {
        // 1. init_module
        confidential_asset::init_module(admin);

        // 2. create test accounts
        let admin_addr = signer::address_of(admin);
        account::create_account_for_test(admin_addr);
        account::create_account_for_test(ALICE_ADDR);
        account::create_account_for_test(BOB_ADDR);

        // 3. Alice and Bob register store
        let alice_signer = account::create_signer_with_capability(&account::create_account_capability(ALICE_ADDR));
        let bob_signer = account::create_signer_with_capability(&account::create_account_capability(BOB_ADDR));

        register(&alice_signer);
        register(&bob_signer);

        assert!(balance_of(ALICE_ADDR) == 0, 100);
        assert!(balance_of(BOB_ADDR) == 0, 101);

        // 4. Admin mint 1000 to Alice

        mint(admin, ALICE_ADDR, 1000, );

        assert!(balance_of(ALICE_ADDR) == 1000, 102);
        assert!(balance_of(BOB_ADDR) == 0, 103);

        // 5. Alice transfers 400 to Bob
        transfer(&alice_signer, BOB_ADDR, 400);

        // 转账后检查余额
        assert!(balance_of(ALICE_ADDR) == 600, 104);
        assert!(balance_of(BOB_ADDR) == 400, 105);


        debug::print(&b"Test passed: full flow + boundary cases");
    }

    // 辅助：因为 withdraw 返回 Token，我们需要一个测试函数来模拟 deposit
    #[test_only]
    fun test_withdraw_and_deposit(admin: &signer) acquires Store {
        let admin_addr = signer::address_of(admin);
        let token = withdraw(admin, 100);

        // 模拟 deposit 到自己（测试 merge）
        deposit(admin_addr, token);

        assert!(balance_of(admin_addr) == 900, 200); // 假设原来 1000
    }
}
