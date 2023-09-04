//! mods: eth_data.move,vector.move
//! word_capacity: 65
script {
    use 0x1::EthData;
    use 0x1::vector;
    fun main() {
        let block_number = 17000000;
        let block_hash = EthData::get_block_hash(block_number);
        let expected = x"96cfa0fb5e50b0a3f6cc76f3299cfbf48f17e8b41798d1394474e67ec8a97e9f";
        assert!(block_hash == expected, 101);
    }
}