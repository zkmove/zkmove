//! circuit: vm
//! step_max_row: 150
//! stack_ops_num: 200
//! locals_ops_num: 100
//! args: 5u64
//! new_args: 7u64
script {
    fun main(n: u64) {
        let i = 0u64;
        while (i < n) {
            i = i + 1;
        };
    }
}