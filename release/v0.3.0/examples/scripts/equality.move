//! mods: token.move
//! args: 1u8,3u8
script {
    use 0x1::Token;

    fun main(a: u8, b: u8) {
        a == b;

        let coin = Token::create(5);
        let coin_1 = Token::create(5);
        let coin_2 = Token::create(6);

        assert!(coin == coin_1, 100);
        assert!(coin != coin_2, 101);

        let ref = &coin;
        let ref_1 = &coin_1;
        let ref_2 = &coin_2;

        assert!(ref == ref_1, 102);
        assert!(ref != ref_2, 103);
    }
}