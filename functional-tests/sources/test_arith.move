module cases::test_arith {
    public entry fun test_arith(x0: u8, x1: u16, x2: u32, x3: u256, y1: u64) {
        // u8 test case
        let x = x0 + 16u8;
        let y = x - (y1 as u8);
        let z = y * 2u8;
        let z = z / 3u8;
        let _w = z % 2u8;

        // u16 test case
        let x = x1 + 20u16;
        let y = x - (y1 as u16);
        let z = y * 2u16;
        let z = z / 3u16;
        let _w = z % 2u16;

        // u32 test case
        let x = x2 + 20u32;
        let y = x - (y1 as u32);
        let z = y * 2u32;
        let z = z / 3u32;
        let _w = z % 2u32;

        // u64 test case
        let x = (x1 as u64) + 20u64;
        let y = x - y1;
        let z = y * 2u64;
        let z = z / 3u64;
        let _w = z % 2u64;

        // u128 test case
        let x = (x2 as u128) + 20u128;
        let y = x - (y1 as u128);
        let z = y * 2u128;
        let z = z / 3u128;
        let _w = z % 2u128;

        // u256 test case
        let x = x3 + 340282366920938463463374607431768211458u256;
        let _y = x - (y1 as u256);
        let z = (y1 as u256) * 2u256;
        let z = z / 3u256;
        let _w = z % 7u256;

        // bitwise operation
        let _l = x3 & 12u256;
        let _m = x3 | 340282366920938463463374607431768211456u256;
        let _n = x3 ^ 255u256;
    }
}
