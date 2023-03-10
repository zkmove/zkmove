//! circuit: vm
script {
    fun main() {
        let i = 0u128;
        while (i < 10u128) {
            i = i + 1;
        };
        assert!(i == 10, 101);
    }
}