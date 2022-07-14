//! circuit: vm
//! steps_num: 1000
//! stack_ops_num: 1000
//! locals_ops_num: 1000
script {
    fun main() {
        let i = 0u64;
        while (i < 10u64) {
            i = i + 1;
        };
        assert!(i == 10, 101);
    }
}