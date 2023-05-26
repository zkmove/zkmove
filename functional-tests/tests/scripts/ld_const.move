//! mods: arith.move
//! args: 10u8
script {
    use 0x1::M;
    fun main(v: u8) {
        M::circle(v);
    }
}