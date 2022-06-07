script {
    fun main() {
        let x = 0u8;
        let y = 1u8;
        let _z = if (x == y) {
            x + y
        } else {
            x * y
        };
    }
}