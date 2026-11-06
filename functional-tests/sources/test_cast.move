module cases::test_cast {
    public entry fun test_cast(x0: u8, x1: u64) {
        let _m = (x1 as u8);
        let _m = (x0 as u16);
        let _m = (x0 as u32);
        let _m = (x0 as u64);
        let _m = (x0 as u128);
        let _m = (x0 as u256);
    }
}
