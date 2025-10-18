module 0x1::vectoring {
    use std::vector;

    public entry fun test_vec_swap() {
        let the_vec: vector<u128> = vector[1, 2, 3, 4];
        vector::swap(&mut the_vec, 2, 3);
    }
}
