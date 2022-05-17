//! circuit: vm
script {
    fun main() {
        let i = 0u64;
        while (i < 10u64) {
            i = i + 1;
        };
        assert(i == 10, 101);
    }
}