//! mods: token.move
script {
    use 0x1::Token;
    fun main() {
        let coin = Token::create_2(100, 99);
        let ref = &coin;
        let read_ref = *ref;
        Token::destroy_2(read_ref);

        let coin_1 = Token::create_2(101, 102);
        let ref_mut = &mut coin;
        *ref_mut = coin_1;
        let amount = Token::value_0(&coin);
        assert!(amount == 101, 100);
    }
}