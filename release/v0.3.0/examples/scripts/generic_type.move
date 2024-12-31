//! mods: generics.move
//! signer: 0x1
//! ty_args: u8
//! args: 0x1, 10u8, 20u8
script {
    use 0x1::Generics;
    fun main<T: store+drop+copy>(account: signer, addr: address, t: T, new_t: T) {
        Generics::create_gt(&account, t);
        let tt = Generics::get_gt(addr);
        assert!(tt==t,100);

        Generics::set_gt(addr, new_t);
        let tt = Generics::destroy_gt<T>(addr);
        assert!(tt ==new_t, 101);
        //Generics::create_gt(&account, s);
        //let _ = Generics::destroy_gt<S>(addr);
    }
}