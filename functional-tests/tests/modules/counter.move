address 0x1 {
module Counter {
    struct Counter has key, store {
        value: u64,
    }

    public fun init(account: &signer) {
        move_to(account, Counter { value: 0 });
    }
}
}