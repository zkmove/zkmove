//! args: 1u8
script {
    fun main(x: u8) {
        let y = x + 2u8;
        assert(y == 3u8, 101);
    }
}