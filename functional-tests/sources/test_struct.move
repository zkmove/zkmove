module cases::test_struct {
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
}
