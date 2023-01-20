//! mods: token.move
script {
    use 0x1::Token;
    fun main() {
        let coin = Token::create(100);
        let ref = &coin;
        let read_ref = *ref;
        Token::destroy(read_ref);

        let coin_1 = Token::create(101);
        let ref_mut = &mut coin;
        *ref_mut = coin_1;
    }
}