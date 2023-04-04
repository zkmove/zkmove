//! mods: generics.move
//! ty_args: u8,bool
//! args: 10u8, false
script {
    use 0x1::Generics;
    fun main<T: copy+drop, S: copy+drop>(t: T, s: S) {
        Generics::save_t_times(t, s, 2);
    }
}