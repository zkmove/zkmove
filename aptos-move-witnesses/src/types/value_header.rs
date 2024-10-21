use crate::types::word::Word;
use move_vm_runtime::witnessing::traced_value::SimpleValue;
use utility::u256::{pair_u128_to_u256, split_u256_to_u128};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader {
    pub flen: u16,
    pub len: u16,
}

impl ValueHeader {
    pub fn new(flen: usize, len: usize) -> Self {
        // Ensure that the values fit within the u16 range
        assert!(flen <= u16::MAX as usize, "flen value exceeds u16 range");
        assert!(len <= u16::MAX as usize, "len value exceeds u16 range");

        ValueHeader {
            flen: flen as u16,
            len: len as u16,
        }
    }
}

impl From<ValueHeader> for SimpleValue {
    fn from(value: ValueHeader) -> SimpleValue {
        SimpleValue::U256(pair_u128_to_u256(value.flen as u128, value.len as u128))
    }
}
impl From<SimpleValue> for ValueHeader {
    fn from(value: SimpleValue) -> ValueHeader {
        match value {
            SimpleValue::U256(v) => {
                let (lo, hi) = split_u256_to_u128(v);
                ValueHeader::new(lo as usize, hi as usize)
            }
            _ => unreachable!(),
        }
    }
}
impl From<Word> for ValueHeader {
    fn from(word: Word) -> ValueHeader {
        let lo = word.lo();
        let hi = word.hi();

        ValueHeader::new(lo as usize, hi as usize)
    }
}
