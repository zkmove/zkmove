//! args: 1u64,2u64,0u8,255u8, 340282366920938463463374607431768211455u256
script {
    fun main(a: u64, b: u64, c: u8, d: u8, e: u256) {
        // lt operator
        let m = a < b;
        assert!(m == true, 101);
        let n = b < a;
        assert!(n == false, 102);
        let o = c < d;
        assert!(o == true, 103);
        let p = d < c;
        assert!(p == false, 104);

        let u = e + 2u256;
        assert!(3u256 < u, 105);
        let v = e + 3u256;
        assert!(u < v, 106);
    }
}