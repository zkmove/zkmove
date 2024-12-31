//! mods: globals.move
//! signer: 0x78560000000000000000000000000000
//! args: 0x78560000000000000000000000000000
script {
    use 0x1::Globals;

    // We haven't implemented Signer.move yet, so we have to pass
    // the same address 0x1 twice, the first time as the signer and
    // the second time as the account address
    fun main(account: signer, addr: address) {
        Globals::new_g(&account, 100);
        let g_value = Globals::read_g(addr);
        assert!(g_value == 100, 101);
        Globals::write_g(addr, 200);
        let g_value = Globals::read_g(addr);
        assert!(g_value == 200, 201);

        Globals::new_gg(&account, 100, 200);
        let (g1,g2) = Globals::read_gg(addr);
        assert!(g1 == 100, 101);
        assert!(g2 == 200, 201);

         Globals::write_gg(addr, 200, 400);
        let (g1, g2) = Globals::read_gg(addr);
        assert!(g1 == 200, 201);
        assert!(g2 == 400, 401);

    }
}