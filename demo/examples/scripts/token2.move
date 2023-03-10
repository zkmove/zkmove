//! mods: token.move
script {
    use 0x1::Token;
    fun main() {
        let coin = Token::create_2(100, 101);
        Token::destroy_2(coin);
    }
}