address 0x1 {
module Counter {
    struct Counter has key, store {
        value: u64,
    }

    public fun init(_account: &signer) {
    }
}
}