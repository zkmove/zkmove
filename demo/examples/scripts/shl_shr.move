//! args: 1u128, 1u256, 127u8, 131u8
script {
    fun main(a0: u128, a1: u256, b0: u8, b1: u8) {
        let x = a0 << b0;
        assert!(x == 170141183460469231731687303715884105728, 100);
        assert!(x >> b0 == a0, 101);

        let x = a1 << b1;
        assert!( x == 2722258935367507707706996859454145691648, 102);
        assert!( x >> b1 == a1, 103);
    }
}
