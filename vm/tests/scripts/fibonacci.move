//! circuit: vm
script {
    fun main() {
        let n = 10u8;
        let value1 = 0u64;
        let value2 = 1u64;
        let fibo = 0u64;

        let i = 0u8;
        while (i < n) {
            fibo = value1 + value2;
            value1 = value2;
            value2 = fibo;
            i = i + 1;
        };
        assert(fibo == 89u64, 101);
    }
}