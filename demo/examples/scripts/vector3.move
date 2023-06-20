//! mods: vector.move
//!word_capacity: 26
script {
    use 0x1::vector;
    fun main() {
        let v = vector::empty();
        let m = vector::empty();
        let n = vector::empty();

        let elem_0 = vector::new_elem(1, 2);
        vector::push_back(&mut v, elem_0);
        let elem_1 = vector::new_elem(3, 4);
        vector::push_back(&mut m, elem_1);
        let elem_2 = vector::new_elem(5, 6);
        vector::push_back(&mut m, elem_2);
        vector::append(&mut v, m);
        
        let elem_3 = vector::new_elem(7, 8);
        vector::push_back(&mut n, elem_3);
        let elem_4 = vector::new_elem(9, 10);
        vector::push_back(&mut n, elem_4);
        vector::append(&mut v, n);

        assert!(vector::length(&v) == 5, 101);
        let elem_ref = vector::borrow(&v, 0);
        let field = vector::elem_field_0(elem_ref);
        assert!(field == 1, 102);
    }
}
