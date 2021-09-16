address 0x1 {
module M {
    public fun add(x: u8, y: u8): u8 {
        x + y
    }
    public fun add_u8(x: u8, y: u8): u8 {
        add(x, y)
    }
}
}