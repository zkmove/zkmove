//! mods: wallet.move
script {
    use 0x1::Wallet;
    fun main() {
        let token = Wallet::new_token(100);
        let token_2 = Wallet::new_token_2(101, 102);
        let wallet = Wallet::create(token, token_2);
        Wallet::value_1_set(&mut wallet, 103);
        let amount = Wallet::value_1(&wallet);
        assert!(amount == 103, 202);
        Wallet::destroy(wallet);
    }
}