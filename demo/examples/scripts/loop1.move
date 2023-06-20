//! circuit: vm
//! step_max_row: 200
//! stack_ops_num: 50
//! locals_ops_num: 50
//! args: 5u64
script {
    fun main(n: u64) {
        let i = 0u64;
        while (i < n) {
            i = i + 1;
        };
    }
}