module cases::Struct_ {

    struct Struct_1 has copy, drop {
        value: u64,
    }

    struct Struct_2 has copy, drop {
        value_0: u64,
        value_1: u64,
    }

    public fun create(value: u64): Struct_1 {
        Struct_1 { value }
    }

    public fun value(s: &Struct_1): u64 {
        s.value
    }

    public fun sub(s: &mut Struct_1, value: u64) {
        s.value = s.value - value;
    }

    public fun add(s: &mut Struct_1, value: u64) {
        s.value = s.value + value;
    }

    public fun destroy(s: Struct_1) {
        let Struct_1 { value: _ } = s;
    }

    public fun create_2(value_0: u64, value_1: u64): Struct_2 {
        Struct_2 { value_0, value_1 }
    }

    public fun value_0(s: &Struct_2): u64 {
        s.value_0
    }

    public fun destroy_2(s: Struct_2) {
        let Struct_2 { value_0: _, value_1: _ } = s;
    }
}