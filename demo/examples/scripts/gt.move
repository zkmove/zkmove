//! args: 1u64,2u64
script {
    fun main(a: u64, b: u64) {
        let m = a > b;
        assert!(m == false, 101);
        let n = b > a;
        assert!(n == true, 102);
    }
}
