//! mods: eth_data.move,vector.move
//! word_capacity: 65
script {
    use 0x1::EthData;
    use 0x1::vector;
    fun main() {
        let block_number = 10000;
        let block_hash = EthData::get_block_hash(block_number);
        assert!(vector::length(&block_hash) == 32, 101);
    }
}