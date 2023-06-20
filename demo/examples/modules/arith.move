address 0x1 {
module M {
    const MAX_INT8: u8 = 255;

    public fun add(x: u8, y: u8): u8 {
        x + y
    }
    public fun add_u8(x: u8, y: u8): u8 {
        add(x, y)
    }
    public fun circle(v: u8): u8 {
        MAX_INT8 - v
    }
}
}