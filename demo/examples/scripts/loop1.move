//! steps_num: 1000
//! stack_ops_num: 1000
//! locals_ops_num: 1000
//! args: 10u64
script {
    fun main(n: u64) {
        let i = 0u64;
        while (i < n) {
            i = i + 1;
        };
    }
}