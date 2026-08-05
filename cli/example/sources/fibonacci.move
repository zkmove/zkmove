module 0x1::fibonacci {
    public entry fun test_fibonacci(n: u64) {
        let value1 = 0u256;
        let value2 = 1u256;
        let fibo = 0u256;

        let i = 0u64;
        while (i < n) {
            fibo = value1 + value2;
            value1 = value2;
            value2 = fibo;
            i = i + 1;
        };
        fibo;
    }
}