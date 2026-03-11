//! args: 1u64, 2u64
//! new-args: 3u64, 1u64
//! word_capacity: 6
script {
    fun main(x: u64, y: u64) {
        assert!(x + y * 2 == 5u64, 101);
    }
}
