//! args: 1u64,2u64,0u8,255u8
script {
    fun main(a: u64, b: u64, c: u8, d: u8) {
        let m = a < b;
        assert!(m == true, 101);
        let n = b < a;
        assert!(n == false, 102);
        let o = c < d;
        assert!(o == true, 103);
        let p = d < c;
        assert!(p == false, 104);
    }
}