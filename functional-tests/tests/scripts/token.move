//! mods: token.move
script {
    use 0x1::Token;
    fun main() {
        let coin = Token::create(100);
        Token::withdraw(&mut coin, 10);
        Token::destroy(coin);
    }
}