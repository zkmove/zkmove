//! mods: token.move
script {
    use 0x1::Token;
    fun main() {
        let coin = Token::create(100);
        let ref = &coin;
        let read_ref = *ref;
        Token::destroy(read_ref);

        let coin_1 = Token::create(90);
        let ref_mut = &mut coin;
        *ref_mut = coin_1;
        let amount = Token::value(&coin);
        assert!(amount == 90, 101);
    }
}