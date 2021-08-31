//! args: 1u64, 2u64
script {
    fun main(x: u64, y: u64) {
        assert(x + y * 2 == 5u64, 101);
    }
}