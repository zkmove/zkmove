//! mods: reference.move
//! args: 1u8, 2u8
script {
    use 0x1::M;
    fun main(x: u8, y: u8) {
        M::add(&mut x, &y);
    }
}