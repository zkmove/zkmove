module cases::test_vector {
    use std::vector;

    public entry fun test_vector() {
        // VecPack
        let v = vector::empty<u64>();
        // VecPushBack
        vector::push_back(&mut v, 5);
        // VecLen
        assert!(vector::length(&v) == 1, 101);
        // VecBorrow
        assert!(*vector::borrow(&v, 0) == 5, 102);

        // VecPushBack
        vector::push_back(&mut v, 6);
        // VecLen
        assert!(vector::length(&v) == 2, 101);

        // VecSwap
        vector::swap(&mut v, 0, 1);

        // VecPopBack
        let value = vector::pop_back(&mut v);
        // EQ
        assert!(value == 5, 103);

        // VecBorrow, WriteRef
        *vector::borrow_mut(&mut v, 0) = 5;

        // VecPopBack
        let value = vector::pop_back(&mut v);
        assert!(value == 5, 103);
        vector::destroy_empty(v);
    }
}
