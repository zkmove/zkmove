//! mods: arith.move, vector.move
//! word_capacity: 12 
//! args: 10u8
script {
    use 0x1::M;
    use 0x1::vector;

    fun main(v: u8) {
        M::circle(v);

        let v = vector[vector[7u8], vector[8u8,9u8]];
        assert!(vector::length(&v) == 2, 101);
    }
}