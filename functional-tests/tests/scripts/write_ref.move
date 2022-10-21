script {
    fun main() {
        let x = 1u8;
        let y = &mut x;
        *y = 2u8;
    }
}
