use crate::step_state::SubIndex;
use move_vm_runtime::witnessing::traced_value::SimpleValue;
use types::Field;

pub trait SubIndexUtils {
    fn into_u128(&self) -> u128;
    fn from_u128(sub_index: u128) -> Self;
    fn parent(&self, depth: usize) -> Option<Self>
    where
        Self: Sized;
}

impl SubIndexUtils for SubIndex {
    fn into_u128(&self) -> u128 {
        unimplemented!()
    }
    fn from_u128(sub_index: u128) -> Self {
        unimplemented!()
    }
    fn parent(&self, depth: usize) -> Option<Self> {
        if depth == 0 {
            None // no parent when sub_index is 0
        } else {
            Some(
                self.iter()
                    .map(|item| *item)
                    .take(depth)
                    .collect::<Vec<usize>>(),
            )
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueHeader {
    pub flen: u16,
    pub len: u16,
}

impl ValueHeader {
    pub fn new(flen: u16, len: u16) -> Self {
        Self { flen, len }
    }

    // The content of the header is compressed into a field element in little-endian order.
    // bit[0..16],  flen
    // bit[16..32], len
    pub fn value(&self) -> u64 {
        (self.flen as u64) + ((self.len as u64) << 16)
    }

    pub fn fe<F: Field>(&self) -> (F, F) {
        (
            F::from_u128(self.flen as u128),
            F::from_u128(self.len as u128),
        )
    }
}

impl From<ValueHeader> for SimpleValue {
    fn from(value: ValueHeader) -> SimpleValue {
        SimpleValue::U64(value.value())
    }
}
impl From<SimpleValue> for ValueHeader {
    fn from(value: SimpleValue) -> ValueHeader {
        match value {
            SimpleValue::U64(v) => {
                let flen = (v & 0xFFFF) as u16;
                let len = ((v & 0xFFFF0000) >> 16) as u16;
                ValueHeader { flen, len }
            }
            _ => unreachable!(),
        }
    }
}
