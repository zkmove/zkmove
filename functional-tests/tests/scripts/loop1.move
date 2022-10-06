//! circuit: vm
//! steps_num: 100
//! stack_ops_num: 100
//! locals_ops_num: 100
//! args: 10u64
script {
    fun main(n: u64) {
        let i = 0u64;
        while (i < n) {
            i = i + 1;
        };
    }
}