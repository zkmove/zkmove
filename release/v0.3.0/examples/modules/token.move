address 0x1 {
module Token {

    struct Coin has copy, drop {
        value: u64,
    }

    struct Coin_2 has copy, drop {
        value_0: u64,
        value_1: u64,
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

    public fun create_2(value_0: u64, value_1: u64): Coin_2 {
        Coin_2 { value_0, value_1 }
    }

    public fun value_0(coin: &Coin_2): u64 {
        coin.value_0
    }

    public fun destroy_2(coin: Coin_2) {
        let Coin_2 { value_0: _, value_1: _ } = coin;
    }
}
}