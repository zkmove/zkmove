//! args: 1u8, 2u8
script {
    fun main(x: u8, y: u8) {
        let a = 0;
        let b = 0;
        if (x == y) {
            a = x + y;
            b = x + y + 1;
        };
        a + b;
    }
}