//! args: 1u8, 2u8
//! steps_num: 50
//! stack_ops_num: 50
//! locals_ops_num: 50
script {
    fun main(x: u8, y: u8) {
        let z;
        if (x == y) {
            z = x + y;
        } else {
            z = x * y;
        };
        z;
    }
}