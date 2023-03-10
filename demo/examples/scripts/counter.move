//! mods: counter.move
//! signer: 0x1
//! args: 0x1
script {
    use 0x1::Counter;

    // We haven't implemented Signer.move yet, so we have to pass
    // the same address 0x1 twice, the first time as the signer and
    // the second time as the account address
    fun main(account: signer, addr: address) {
        Counter::init(&account);
        let is_exist = Counter::check(addr);
        assert!(is_exist, 101);
        Counter::incr(addr);
        let value = Counter::value(addr);
        assert!(value == 1, 102);
        Counter::delete(addr);


        Counter::init_nested_counter(&account);
        Counter::delete_nested_counter(addr);
    }
}