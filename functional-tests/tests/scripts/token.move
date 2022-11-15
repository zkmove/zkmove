//! mods: token.move
script {
    use 0x1::Token;
    fun main() {
        let coin = Token::create(100);
        Token::withdraw(&mut coin, 10);
        let amount = Token::value(&coin);
        assert!(amount == 90, 101);
        Token::deposit(&mut coin, 10);
        let amount = Token::value(&coin);
        assert!(amount == 100, 101);
        Token::destroy(coin);
    }
}