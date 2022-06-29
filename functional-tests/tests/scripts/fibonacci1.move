//! args: 10u64
//! steps_num: 1000
//! stack_ops_num: 1000
//! locals_ops_num: 1000
script {
    fun main(n: u64) {
        let value1 = 0u64;
        let value2 = 1u64;
        let fibo = 0u64;

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
