//! args: 1u64,2u64,3u64,3u64
script {
    fun main(a: u64, b: u64, c: u64, d: u64) {
        let m = a <= b;
        assert!(m == true, 101);
        let n = b <= a;
        assert!(n == false, 102);
        let o = c <= d;
        assert!(o == true, 103);
    }
}
