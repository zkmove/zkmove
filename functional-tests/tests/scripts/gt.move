//! args: 1u64,2u64,340282366920938463463374607431768211455u256
script {
    fun main(a: u64, b: u64, c: u256) {
        let m = a > b;
        assert!(m == false, 101);
        let n = b > a;
        assert!(n == true, 102);

        let u = c + 2u256;
        assert!(u > 3u256, 105);
        let v = c + 3u256;
        assert!(v > u, 106);
    }
}
