address 0x1 {
module Counter {
    struct Counter has key, store {
        value: u64,
    }

    public fun init(account: &signer) {
        move_to(account, Counter { value: 0 });
    }

    public fun check(addr: address): bool {
        exists<Counter>(addr)
    }

    public fun incr(addr: address) acquires Counter {
        let _counter = borrow_global_mut<Counter>(addr);
        //counter.value = counter.value + 1;
    }

    public fun value(addr: address): u64 acquires Counter {
        let counter = borrow_global<Counter>(addr);
        counter.value
    }

    public fun delete(account: address) acquires Counter {
        let Counter { value: _ } = move_from<Counter>(account);
    }
}
}