use crate::sub_index::SubIndex;
use crate::word::Word;
use field_exts::util::Scalar;
use field_exts::Field;
use move_vm_runtime::witnessing::traced_value::ValueItem;

pub trait ToScalars<F: Field> {
    /// Returns a vector of scalars for the type.
    fn to_scalars(&self) -> Vec<F>;
}

impl<F: Field> ToScalars<F> for ValueItem {
    fn to_scalars(&self) -> Vec<F> {
        vec![
            SubIndex::new(self.sub_index.clone()).scalar(),
            self.header.scalar(),
        ]
        .into_iter()
        .chain(Word::from(&self.value).to_scalars())
        .collect()
    }
}
