//! mods: wallet.move
//!word_capacity: 25
script {
    use 0x1::Wallet;
    fun main() {
        let token = Wallet::new_token(100);
        let token_2 = Wallet::new_token_2(101, 102);
        let wallet_1 = Wallet::create(token, token_2);
        Wallet::value_1_set(&mut wallet_1, 103);
        let amount = Wallet::value_1(&wallet_1);
        assert!(amount == 103, 202);

        let _walletset = Wallet::walletset_create(wallet_1, wallet_1);
        // let _walletset2 = Wallet::walletset_create2(walletset, walletset);

        Wallet::destroy(wallet_1);
    }
}