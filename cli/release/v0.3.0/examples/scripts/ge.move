//! args: 1u64,2u64,3u64,3u64,340282366920938463463374607431768211455u256
script {
    fun main(a: u64, b: u64, c: u64, d: u64, e: u256) {
        let m = a >= b;
        assert!(m == false, 101);
        let n = b >= a;
        assert!(n == true, 102);
        let o = c >= d;
        assert!(o == true, 103);

        let u = e + 2u256;
        assert!(u >= 3u256, 105);
        let v = e + 2u256;
        assert!(u >= v, 106);
    }
}
