//! mods: generics.move
//! ty_args: u8,bool
//! args: 10u8, false
//! new_args: false,10u8
//! new_ty_args: bool,u8
script {
    use 0x1::Generics;
    fun main<T: copy+drop, S: copy+drop>(t: T, s: S) {
        Generics::save_t_times(t, s, 2);
    }
}