//! mods: wallet.move
script {
    use 0x1::Wallet;
    fun main() {
        let token = Wallet::new_token(100);
        let token_2 = Wallet::new_token_2(101, 102);
        let wallet = Wallet::create(token, token_2);
//        let amount = Wallet::value(&wallet);
//        assert!(amount == 100, 101);
        Wallet::destroy(wallet);
    }
}