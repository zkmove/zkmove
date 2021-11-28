//! args: 1u8, 2u8
script {
    fun main(x: u8, y: u8) {
        let a;
        let b;
        if (x == y) {
            a = x + y;
            b = x + y + 1;
        } else {
            a = x * y;
            b = x * y + 1;
        };
        a + b;
    }
}