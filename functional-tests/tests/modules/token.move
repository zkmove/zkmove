address 0x1 {
module Token {

    struct Coin {
        value: u64,
    }

    public fun create(value: u64): Coin {
        Coin { value }
    }

    public fun value(coin: &Coin): u64 {
        coin.value
    }

    public fun withdraw(coin: &mut Coin, amount: u64) {
        coin.value = coin.value - amount;
    }

    public fun deposit(coin: &mut Coin, amount: u64) {
        coin.value = coin.value + amount;
    }

    public fun destroy(coin: Coin) {
        let Coin { value: _ } = coin;
    }
}
}