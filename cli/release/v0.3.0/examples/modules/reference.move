address 0x1 {
module M {
    public fun add(x: &mut u8, y: &u8): u8 {
        *x = 3u8;
        *x + *y
    }
}
}