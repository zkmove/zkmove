//! args: 2u8
script {
    fun main(x: u8) {
        let y = x - 1u8;
        assert(y == 1u8, 101);
    }
}