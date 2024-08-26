module 0x1::TestCase {
    public entry fun test_abort() {
        assert!(3 == 3, 101);
    }

    public entry fun test_add() {
        1u8 + 2u8;
    }

    public entry fun test_add_u64(x: u64, y: u64) {
        x + y;
    }

    public entry fun test_arith_integer(x1: u16, x2: u32, x3: u256, y: u64) {
        // u16 test case
        // add operation
        let x = x1 + 20u16;
        // cast operation
        let y = x - (y as u16);
        // multiple operation
        let z = y * 2u16;
        // divide operation
        let z = z / 3u16;
        // modulo operation
        let _w = z % 2u16;

        // u32 test case
        // add operation
        let x = x2 + 20u32;
        // cast operation
        let y = x - (y as u32);
        // multiple operation
        let z = y * 2u32;
        // divide operation
        let z = z / 3u32;
        // modulo operation
        let _w = z % 2u32;

        // u256 test case
        // add operation
        let x = x3 + 340282366920938463463374607431768211458u256;
        // cast operation
        let y = x - (y as u256);
        // multiple operation
        let z = y * 100u256;
        // divide operation
        let z = z / 3u256;
        // modulo operation
        let _w = z % 7u256;

        // u256 bitwise operation
        let _l = x3 & 127u256;
        let _m = x3 | 340282366920938463463374607431768211456u256;
        let _n = x3 ^ 255u256;
    }
}