//! word_capacity: 97
//! module_id: 0x1::EthData
//! entry_fun: eth_data
module 0x1::EthData {
    /// get the block hash at a specific block_number
    native public fun get_block_hash(block_number: u64): vector<u8>;
    /// get slot value at a address in a block number
    /// TODO: change slot and return value to u256
    native public fun get_slot(block_number: u64, address: vector<u8>, slot: u128): u128;

    public entry fun  eth_data(): vector<u8> {
        let block_number = 17000000;
        let block_hash = get_block_hash(block_number);
        let expected = x"96cfa0fb5e50b0a3f6cc76f3299cfbf48f17e8b41798d1394474e67ec8a97e9f";
        assert!(block_hash == expected, 101);
        // FIXME: Error::InstanceTooLarge
        // block_hash
        x"96cf"
    }
 }