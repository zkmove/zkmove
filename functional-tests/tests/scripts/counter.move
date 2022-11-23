//! mods: counter.move
//! args: 0x1
script {
    use 0x1::Counter;

    fun main(account: signer) {
        Counter::init(&account);
    }
}