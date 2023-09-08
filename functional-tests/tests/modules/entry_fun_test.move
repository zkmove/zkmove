//! mods: arith.move
//! module_id: 0x1::Entry_Fun_Test
//! entry_fun: entry_function_test
//! args: 1u8, 2u8
address 0x1 {
module Entry_Fun_Test {
    use 0x1::M;
    public entry fun entry_function_test(x: u8, y: u8) {
        M::add_u8(x, y);
    }
}
}