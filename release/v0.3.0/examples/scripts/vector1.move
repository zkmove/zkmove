//! mods: vector.move
script {
    use 0x1::vector;
    fun main() {
        let v = vector::empty();
        vector::push_back(&mut v, 5);
        assert!(vector::length(&v) == 1, 101);
        assert!(*vector::borrow(&v, 0) == 5, 102);
        let value = vector::pop_back(&mut v);
        assert!(value == 5, 103);
        vector::destroy_empty(v);
    }
}
