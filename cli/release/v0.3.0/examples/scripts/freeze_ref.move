script {
    fun main() {
        let x = 1u8;
        let y = &mut x;
        let _z = freeze(y);
    }
}
