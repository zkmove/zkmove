//! mods: vector.move
script {
    use 0x1::vector;
    fun main() {
        let v = vector::empty();

        let elem_0 = vector::new_elem(1, 2);
        vector::push_back(&mut v, elem_0);
        let elem_1 = vector::new_elem(3, 4);
        vector::push_back(&mut v, elem_1);

        assert!(vector::length(&v) == 2, 101);
        let elem_ref = vector::borrow(&v, 0);
        let field = vector::elem_field_0(elem_ref);
        assert!(field == 1, 102);
    }
}
