//! steps_num: 1000
//! stack_ops_num: 1000
//! locals_ops_num: 1000
//! args: 11u8
script {
    fun main(n: u8) {
        let value1 = 0u128;
        let value2 = 1u128;
        let fibo = 0u128;

        let i = 0u8;
        while (i < n) {
            fibo = value1 + value2;
            value1 = value2;
            value2 = fibo;
            i = i + 1;
        };
        fibo;
//        assert!(fibo == 573147844013817084101, 101);
    }
}