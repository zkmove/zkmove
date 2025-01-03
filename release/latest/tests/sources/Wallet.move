module cases::Wallet {

    struct Token has copy, drop {
        value: u64,
    }

    struct Token_2 has copy, drop {
        value_0: u64,
        value_1: u64,
    }

    struct Wallet has copy, drop {
        token: Token,
        token_2: Token_2,
    }

    struct WalletSet has copy, drop {
        wallet_1: Wallet,
        wallet_2: Wallet,
    }

    struct WalletSet2 has copy, drop {
        wallet_1: WalletSet,
        wallet_2: WalletSet,
    }

    public fun new_token(value: u64): Token {
        Token { value }
    }

    public fun new_token_2(value_0: u64, value_1: u64): Token_2 {
        Token_2 { value_0, value_1 }
    }

    public fun create(token: Token, token_2: Token_2): Wallet {
        Wallet { token, token_2 }
    }

    public fun walletset_create(wallet_1: Wallet, wallet_2: Wallet): WalletSet {
        WalletSet { wallet_1, wallet_2 }
    }

    public fun walletset_create2(w_1: WalletSet, w_2: WalletSet): WalletSet2 {
        WalletSet2 { wallet_1: w_1, wallet_2: w_2 }
    }

    public fun value(wallet: &Wallet): u64 {
        wallet.token.value
    }

    public fun value_1(wallet: &Wallet): u64 {
        wallet.token_2.value_1
    }

    public fun value_1_set(wallet: &mut Wallet, amount: u64) {
        wallet.token_2.value_1 = amount;
    }

    public fun destroy(wallet: Wallet) {
        let Wallet { token: token, token_2: token_2 } = wallet;
        let Token { value: _ } = token;
        let Token_2 { value_0: _, value_1: _ } = token_2;
    }
}