//! args: true,false
script {
    fun main(a: bool, b: bool) {
        let c = a && b;
        assert(c == false, 101);
        let d = a || b;
        assert(d == true, 102);
    }
}