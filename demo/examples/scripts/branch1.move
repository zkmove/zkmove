//! args: 1u8, 2u8
//! step_max_row: 200
//! stack_ops_num: 50
//! locals_ops_num: 50
script {
    fun main(x: u8, y: u8) {
        let a = 0;
        let b = 0;
        if (x == y) {
            a = x + y;
            b = x + y + 1;
        };
        a + b;
    }
}