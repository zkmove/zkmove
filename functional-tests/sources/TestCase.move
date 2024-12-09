module cases::TestCase {
    use std::vector;
    use cases::Wallet;

    public entry fun test_all() {
        //test_abort();
        test_add();
        test_call();
        test_add_loop();
        test_cast(1, 2);
        test_arith(1, 2, 3, 10u256, 1);
        test_vector();
        test_wallet();
        test_struct();
    }

    public entry fun test_abort() {
        assert!(3 == 3, 101);
        assert!(3 == 4, 102);
    }

    public entry fun test_add() {
        1u8 + 2u8;
    }

    public entry fun test_call() {
        test_call_(2);
    }

    public fun test_call_(i: u8) {
        if (i > 0) {
            test_call_(i - 1);
        };
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

    public entry fun test_cast(x0: u8, x1: u64) {
        let _m = (x1 as u8);
        let _m = (x0 as u16);
        let _m = (x0 as u32);
        let _m = (x0 as u64);
        let _m = (x0 as u128);
        let _m = (x0 as u256);
    }

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


    public entry fun test_vector() {
        // VecPack
        let v = vector::empty<u64>();
        // VecPushBack
        vector::push_back(&mut v, 5);
        // VecLen
        assert!(vector::length(&v) == 1, 101);
        // VecBorrow
        assert!(*vector::borrow(&v, 0) == 5, 102);

        // VecPushBack
        vector::push_back(&mut v, 6);
        // VecLen
        assert!(vector::length(&v) == 2, 101);

        // VecSwap
        vector::swap(&mut v, 0, 1);

        // VecPopBack
        let value = vector::pop_back(&mut v);
        // EQ
        assert!(value == 5, 103);

        // VecBorrow, WriteRef
        *vector::borrow_mut(&mut v, 0) = 5;

        // VecPopBack
        let value = vector::pop_back(&mut v);
        assert!(value == 5, 103);
        vector::destroy_empty(v);
    }

    public entry fun test_comp(a: u64, b: u64, c: u64, d: u64, e: u256) {
        let m = a >= b;
        assert!(m == false, 101);
        let n = b > a;
        assert!(n == true, 102);
        let o = d < c;
        assert!(o == false, 103);
        let p = d <= c;
        assert!(p == true, 104);

        assert!(e >= 3u256, 105);
        assert!(e > 3u256, 106);
        assert!(3u256 < e, 107);
        assert!(3u256 <= e, 108);
    }

    public entry fun test_logical(a: bool, b: bool) {
        if (a != b) {
            a;
        };
        let c = a && b;
        assert!(c == false, 101);
        let d = a || b;
        assert!(d == true, 102);
        let e = !a;
        assert!(e == false, 103);
    }

    public entry fun test_shift(a0: u128, a1: u256, b0: u8, b1: u8) {
        let x = a0 << b0;
        assert!(x == 170141183460469231731687303715884105728, 100);
        assert!(x >> b0 == a0, 101);

        let x = a1 << b1;
        assert!(x == 2722258935367507707706996859454145691648, 102);
        assert!(x >> b1 == a1, 103);
    }

    public entry fun test_wallet() {
        let token = Wallet::new_token(100);
        let token_2 = Wallet::new_token_2(101, 102);
        let wallet_1 = Wallet::create(token, token_2);
        Wallet::value_1_set(&mut wallet_1, 103);
        let amount = Wallet::value_1(&wallet_1);
        assert!(amount == 103, 202);

        let walletset = Wallet::walletset_create(wallet_1, wallet_1);
        let _walletset2 = Wallet::walletset_create2(walletset, walletset);

        Wallet::destroy(wallet_1);
    }

    use cases::Struct_;

    public entry fun test_struct() {
        let s = Struct_::create(100);
        Struct_::sub(&mut s, 10);
        let amount = Struct_::value(&s);
        assert!(amount == 90, 1);
        Struct_::add(&mut s, 10);
        let amount = Struct_::value(&s);
        assert!(amount == 100, 2);
        Struct_::destroy(s);

        let s = Struct_::create_2(100, 99);
        let ref = &s;
        let read_ref = *ref;
        Struct_::destroy_2(read_ref);
        let s_new = Struct_::create_2(101, 102);
        let ref_mut = &mut s;
        *ref_mut = s_new;
        let amount = Struct_::value_0(&s);
        assert!(amount == 101, 3);
    }
    public entry fun test_fibonacci(n: u64) {
        let value1 = 0u256;
        let value2 = 1u256;
        let fibo = 0u256;

        let i = 0u64;
        while (i < n) {
            fibo = value1 + value2;
            value1 = value2;
            value2 = fibo;
            i = i + 1;
        };
        fibo;
    }
}