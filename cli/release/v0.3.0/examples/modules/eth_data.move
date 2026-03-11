module 0x1::EthData {
    /// get the block hash at a specific block_number
    native public fun get_block_hash(block_number: u64): vector<u8>;
    /// get slot value at a address in a block number
    /// TODO: change slot and return value to u256
    native public fun get_slot(block_number: u64, address: vector<u8>, slot: u128): u128;

 }