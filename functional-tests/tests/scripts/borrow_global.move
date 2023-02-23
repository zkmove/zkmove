//! mods: globals.move
//! signer: 0x1
//! args: 0x1
script {
    use 0x1::Globals;

    // We haven't implemented Signer.move yet, so we have to pass
    // the same address 0x1 twice, the first time as the signer and
    // the second time as the account address
    fun main(account: signer, addr: address) {
        Globals::new_g(&account, 100);
        Globals::borrow_g(addr);
        let g_value = Globals::read_g(addr);
        assert!(g_value == 100, 101);
        Globals::borrow_mut_g(addr);
    }
}