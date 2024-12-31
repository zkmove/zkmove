//! args: 1u8, 2u8
script {
    fun main(x: u8, y: u8) {
        let _z = if (x == y) {
            1
        } else {
            0
        };
    }
}