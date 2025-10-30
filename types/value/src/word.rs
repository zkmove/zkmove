use crate::sub_index::SubIndex;
use crate::utils::{ToField, ToFields};
use crate::value_header::ValueHeader;
use crate::word_generic::WordLoHi;
use field_exts::util::pow_of_two;
use field_exts::Field;
use move_core_types::account_address::AccountAddress;
use move_core_types::u256::U256;
use move_vm_runtime::witnessing::traced_value::{Integer, Reference, SimpleValue};

// #[derive(Clone, Eq, Copy, PartialEq, Debug, Default)]
// pub struct Word([u128; 2]);

pub type Word = WordLoHi<u128>;

// impl Word {
//     pub fn inner(&self) -> [u128; 2] {
//         self.0
//     }
//     pub fn lo(&self) -> u128 {
//         self.0[0]
//     }
//     pub fn hi(&self) -> u128 {
//         self.0[1]
//     }
//     pub fn to_u256(&self) -> U256 {
//         pair_u128_to_u256(self.lo(), self.hi())
//     }
//     pub fn to_u8_unchecked(&self) -> u8 {
//         (self.lo() & 0xFF) as u8
//     }
// }
//
// impl From<(u128, u128)> for Word {
//     fn from(pair: (u128, u128)) -> Self {
//         Word([pair.0, pair.1])
//     }
// }
//
impl From<bool> for Word {
    fn from(b: bool) -> Self {
        Word::new([b as u128, 0u128])
    }
}

impl From<&Reference> for Word {
    fn from(r: &Reference) -> Self {
        let frame_index = r.frame_index as u128;
        let local_index = r.local_index as u128;

        // Convert the Vec<usize> into a SubIndex and then into a u128
        let sub_index: u128 = SubIndex::from(r.sub_index.clone()).into();

        // Pack frame_index and local_index into lo, and sub_index into hi
        let lo = frame_index | (local_index << 16);
        let hi = sub_index;

        Word::new([lo, hi])
    }
}
impl From<Reference> for Word {
    fn from(r: Reference) -> Self {
        (&r).into()
    }
}

impl From<&AccountAddress> for Word {
    fn from(addr: &AccountAddress) -> Self {
        let bytes = addr.into_bytes();

        let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());

        Word::new([lo, hi])
    }
}
impl From<&SimpleValue> for Word {
    fn from(value: &SimpleValue) -> Self {
        match value {
            SimpleValue::U8(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U16(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U32(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U64(u) => Word::new([*u as u128, 0u128]),
            SimpleValue::U128(u) => Word::new([*u, 0u128]),
            SimpleValue::U256(u) => {
                let bytes = u.to_le_bytes();
                let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
                let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
                Word::new([lo, hi])
            }
            SimpleValue::Bool(b) => Word::new([*b as u128, 0u128]),
            SimpleValue::Reference(r) => Word::from(r),
            SimpleValue::Address(a) => Word::from(a),
        }
    }
}

impl From<SimpleValue> for Word {
    fn from(value: SimpleValue) -> Self {
        (&value).into()
    }
}

impl From<&Integer> for Word {
    fn from(value: &Integer) -> Self {
        let (lo, hi) = match value {
            Integer::U8(v) => (*v as u128, 0u128),
            Integer::U16(v) => (*v as u128, 0u128),
            Integer::U32(v) => (*v as u128, 0u128),
            Integer::U64(v) => (*v as u128, 0u128),
            Integer::U128(v) => (*v, 0u128),
            Integer::U256(v) => {
                let bytes = v.to_le_bytes();
                let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
                let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
                (lo, hi)
            }
        };
        Word::new([lo, hi])
    }
}

impl From<Integer> for Word {
    fn from(value: Integer) -> Self {
        (&value).into()
    }
}
impl From<ValueHeader> for Word {
    fn from(header: ValueHeader) -> Self {
        let lo = header.flen as u128; // Store flen in the lower 16 bits of lo
        let hi = header.len as u128; // Store len in the lower 16 bits of hi

        Word::new([lo, hi])
    }
}

impl<F: Field> ToFields<F> for Word {
    fn to_fields(&self) -> Vec<F> {
        vec![F::from_u128(self.lo()), F::from_u128(self.hi())]
    }
}
impl<F: Field> ToField<F> for Word {
    fn to_field(&self) -> F {
        F::from_u128(self.hi()) * pow_of_two::<F>(128) + F::from_u128(self.lo())
    }
}
