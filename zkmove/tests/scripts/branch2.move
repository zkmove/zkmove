//! args: 1u8, 2u8
script {
    fun main(x: u8, y: u8) {
        let z;
        if (x == y) {
            z = x + y;
        } else {
            z = x * y;
        };
        z;
    }
}