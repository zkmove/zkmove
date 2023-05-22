module 0x1::vector {

    #[bytecode_instruction]
    /// Create an empty vector.
    native public fun empty<Element>(): vector<Element>;

    #[bytecode_instruction]
    /// Return the length of the vector.
    native public fun length<Element>(v: &vector<Element>): u64;

    #[bytecode_instruction]
    /// Acquire an immutable reference to the `i`th element of the vector `v`.
    /// Aborts if `i` is out of bounds.
    native public fun borrow<Element>(v: &vector<Element>, i: u64): &Element;

    #[bytecode_instruction]
    /// Add element `e` to the end of the vector `v`.
    native public fun push_back<Element>(v: &mut vector<Element>, e: Element);

    #[bytecode_instruction]
    /// Return a mutable reference to the `i`th element in the vector `v`.
    /// Aborts if `i` is out of bounds.
    native public fun borrow_mut<Element>(v: &mut vector<Element>, i: u64): &mut Element;

    #[bytecode_instruction]
    /// Pop an element from the end of vector `v`.
    /// Aborts if `v` is empty.
    native public fun pop_back<Element>(v: &mut vector<Element>): Element;

    #[bytecode_instruction]
    /// Destroy the vector `v`.
    /// Aborts if `v` is not empty.
    native public fun destroy_empty<Element>(v: vector<Element>);

    #[bytecode_instruction]
    /// Swaps the elements at the `i`th and `j`th indices in the vector `v`.
    /// Aborts if `i`or `j` is out of bounds.
    native public fun swap<Element>(v: &mut vector<Element>, i: u64, j: u64);

    /// Return an vector of size one containing element `e`.
    public fun singleton<Element>(e: Element): vector<Element> {
        let v = empty();
        push_back(&mut v, e);
        v
    }

    /// Reverses the order of the elements in the vector `v` in place.
    public fun reverse<Element>(v: &mut vector<Element>) {
        let len = length(v);
        if (len == 0) return ();

        let front_index = 0;
        let back_index = len - 1;
        while (front_index < back_index) {
            swap(v, front_index, back_index);
            front_index = front_index + 1;
            back_index = back_index - 1;
        }
    }

    /// Pushes all of the elements of the `other` vector into the `lhs` vector.
    public fun append<Element>(lhs: &mut vector<Element>, other: vector<Element>) {
        reverse(&mut other);
        while (!is_empty(&other)) push_back(lhs, pop_back(&mut other));
        destroy_empty(other);
    }

    /// Return `true` if the vector `v` has no elements and `false` otherwise.
    public fun is_empty<Element>(v: &vector<Element>): bool {
        length(v) == 0
    }

//    //issue #105
//    /// Return true if `e` is in the vector `v`.
//    public fun contains<Element>(v: &vector<Element>, e: &Element): bool {
//        let i = 0;
//        let len = length(v);
//        while (i < len) {
//            if (borrow(v, i) == e) return true;
//            i = i + 1;
//        };
//        false
//    }

    /// Return `(true, i)` if `e` is in the vector `v` at index `i`.
    /// Otherwise, returns `(false, 0)`.
    public fun index_of<Element>(v: &vector<Element>, e: &Element): (bool, u64) {
        let i = 0;
        let len = length(v);
        while (i < len) {
            if (borrow(v, i) == e) return (true, i);
            i = i + 1;
        };
        (false, 0)
    }

    /// Remove the `i`th element of the vector `v`, shifting all subsequent elements.
    /// This is O(n) and preserves ordering of elements in the vector.
    /// Aborts if `i` is out of bounds.
    public fun remove<Element>(v: &mut vector<Element>, i: u64): Element {
        let len = length(v);
        // i out of bounds; abort
        if (i >= len) abort 0;

        len = len - 1;
        while (i < len) swap(v, i, { i = i + 1; i });
        pop_back(v)
    }

    /// Swap the `i`th element of the vector `v` with the last element and then pop the vector.
    /// This is O(1), but does not preserve ordering of elements in the vector.
    /// Aborts if `i` is out of bounds.
    public fun swap_remove<Element>(v: &mut vector<Element>, i: u64): Element {
        assert!(!is_empty(v), 0);
        let last_idx = length(v) - 1;
        swap(v, i, last_idx);
        pop_back(v)
    }

    /// For testing purposes only
    struct Elem has copy, drop {
        e0: u8,
        e1: u8,
    }
    public fun new_elem(e0: u8, e1: u8): Elem {
        Elem { e0, e1 }
    }
    public fun elem_field_0(e: &Elem): u8 {
        e.e0
    }

    struct G has key, store {
        vec: vector<u64>,
    }
    public fun new_g(account: &signer, value: u64) {
        let vec = empty<u64>();
        push_back(&mut vec, value);
        move_to(account, G { vec });
    }
    public fun read_value(addr: address): u64 acquires G {
        let g = borrow_global<G>(addr);
        let value = borrow(&g.vec, 0);
        *value
    }
    public fun write_value(addr: address, value: u64) acquires G {
        let new_vec = empty<u64>();
        push_back(&mut new_vec, value);
        let g = borrow_global_mut<G>(addr);
        g.vec = new_vec
    }
    public fun vec_len(addr: address): u64 acquires G {
        let g = borrow_global<G>(addr);
        length(&g.vec)
    }
    public fun g_push_back(addr: address, value: u64) acquires G {
        let g = borrow_global_mut<G>(addr);
        push_back(&mut g.vec, value);
    }
    public fun g_pop_back(addr: address):u64 acquires G {
        let g = borrow_global_mut<G>(addr);
        pop_back(&mut g.vec)
    }
    public fun g_swap(addr: address, i: u64, j: u64) acquires G {
        let g = borrow_global_mut<G>(addr);
        swap(&mut g.vec, i, j);
    }
}