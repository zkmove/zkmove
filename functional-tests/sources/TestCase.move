module cases::TestCase {
    use std::vector;

    public entry fun test_abort() {
        assert!(3 == 3, 101);
    }

    public entry fun test_add() {
        1u8 + 2u8;
    }

    public entry fun test_add_loop() {
        let i = 10u64;
        let t = 0;
        loop {
            t = t + i;
            if (i == 0) {
                break
            };
            i = i - 1;
        }
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


    public entry fun test_vector() {
        let v = vector::empty<u64>();
        vector::destroy_empty(v);
        //vector::push_back(&mut v, 5);
        // assert!(vector::length(&v) == 1, 101);
        // assert!(*vector::borrow(&v, 0) == 5, 102);
        //
        // vector::push_back(&mut v, 6);
        // assert!(vector::length(&v) == 2, 101);
        //
        // vector::swap(&mut v, 0, 1);
        //
        // let value = vector::pop_back(&mut v);
        // assert!(value == 5, 103);
        // vector::pop_back(&mut v);
        // vector::destroy_empty(v);
    }
}