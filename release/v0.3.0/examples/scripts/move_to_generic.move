//! mods: generics.move
//! signer: 0x1
//! ty_args: u8,bool
//! args: 0x1, 10u8, false
script {
    use 0x1::Generics;
    fun main<T: store+drop, S: store+drop>(account: signer, _addr: address, t: T, s: S) {
        Generics::create_gt(&account, t);
        //Generics::create_gt(&account, s);
    }
}