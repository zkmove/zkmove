//! mods: arith.move
script {
    use 0x1::M;
    fun main() {
        let x = 1u8;
        let y = 2u8;
        M::add(x, y);
    }
}