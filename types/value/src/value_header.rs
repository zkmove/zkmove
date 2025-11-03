use crate::to_u256::{pair_u128_to_u256, split_u256_to_u128};
use crate::word::Word;
use field_exts::Field;
use halo2_proofs::plonk::Expression;
use move_vm_runtime::witnessing::traced_value::SimpleValue;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader<T> {
    pub flen: T,
    pub len: T,
}

impl ValueHeader<u16> {
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

impl From<ValueHeader<u16>> for SimpleValue {
    fn from(value: ValueHeader<u16>) -> SimpleValue {
        SimpleValue::U256(pair_u128_to_u256(value.flen as u128, value.len as u128))
    }
}
impl From<SimpleValue> for ValueHeader<u16> {
    fn from(value: SimpleValue) -> ValueHeader<u16> {
        match value {
            SimpleValue::U256(v) => {
                let (lo, hi) = split_u256_to_u128(v);
                ValueHeader::new(lo as usize, hi as usize)
            }
            _ => unreachable!(),
        }
    }
}

impl From<Word> for ValueHeader<u16> {
    fn from(word: Word) -> ValueHeader<u16> {
        let lo = word.lo();
        let hi = word.hi();

        ValueHeader::new(lo as usize, hi as usize)
    }
}

impl<F: Field> ValueHeader<Expression<F>> {
    pub fn flen(&self) -> Expression<F> {
        self.flen.clone()
    }
    pub fn len(&self) -> Expression<F> {
        self.len.clone()
    }
    pub fn pair(len: Expression<F>, flen: Expression<F>) -> Self {
        Self { flen, len }
    }
}
