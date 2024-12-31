//! mods: vector.move
script {
    use 0x1::vector;
    fun main() {
        let v1 = vector::empty<u64>();
        vector::push_back(&mut v1, 2);
        let v2 = vector::empty<u64>();
        vector::push_back(&mut v2, 3);
        vector::append(&mut v1, v2);
        vector::swap(&mut v1, 0, 1);
        assert!(*vector::borrow(&v1, 0) == 3, 103);
        assert!(*vector::borrow(&v1, 1) == 2, 104);
        //assert!(vector::contains(&v1, &3), 105); //issue #105
    }
}
