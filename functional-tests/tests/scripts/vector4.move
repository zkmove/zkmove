//! mods: vector.move
//! signer: 0x78560000000000000000000000000000
//! args: 0x78560000000000000000000000000000
script {
    use 0x1::vector;

    // We haven't implemented Signer.move yet, so we have to pass
    // the same address 0x1 twice, the first time as the signer and
    // the second time as the account address
    fun main(account: signer, addr: address) {
        vector::new_g(&account, 1);
        let v = vector::read_value(addr);
        assert!(v == 1, 100);

        vector::write_value(addr, 2);
        let v = vector::read_value(addr);
        assert!(v == 2, 101);
        assert!(vector::vec_len(addr) == 1, 102);

        vector::g_push_back(addr, 3);
        assert!(vector::vec_len(addr) == 2, 103);

        vector::g_swap(addr, 0, 1);
        let value = vector::g_pop_back(addr);
        assert!(value == 2, 104);
        assert!(vector::vec_len(addr) == 1, 105);
    }
}