use field_exts::util::from_limbs;
use field_exts::util::Scalar;
use field_exts::Field;

/// Number of limbs (dimensions) of a `SubIndex`.
pub const N_LIMBS: usize = 4;
/// Number of bits of a single limb (elements per dimension).
pub const N_BITS_ONE_LIMB: usize = 16;
/// Number of bytes used to encode a `SubIndex` (little endian).
pub const NUM_OF_BYTES_SUB_INDEX: usize = N_LIMBS * N_BITS_ONE_LIMB / 8;

/// The relative position of an element within a complex value: a path of at
/// most [`N_LIMBS`] dimensions, each holding at most `2^N_BITS_ONE_LIMB`
/// elements.  It is encoded as a `u64` (little endian limbs), so ordering is
/// only defined once the value is treated as an integer.
#[derive(Default, Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct SubIndex([u16; N_LIMBS]);

impl SubIndex {
    pub fn new(sub_index: Vec<usize>) -> Self {
        assert!(
            sub_index.len() <= N_LIMBS,
            "sub_index depth {} exceeds the maximum supported depth {}",
            sub_index.len(),
            N_LIMBS
        );

        let mut result = [0u16; N_LIMBS];
        for (i, &val) in sub_index.iter().enumerate() {
            assert!(
                val <= u16::MAX as usize,
                "Value {} exceeds the maximum value for u16",
                val
            );
            result[i] = val as u16;
        }

        SubIndex(result)
    }

    pub fn depth(&self) -> usize {
        self.0
            .iter()
            .rposition(|&x| x != 0)
            .map_or(0, |pos| pos + 1)
    }

    /// A depth-n sub_index must have n parents. Return all parents in a vector, in a order
    /// starting with direct relatives. For example,
    /// [1,2,3,0]'s parents is [[1,2,0,0],[1,0,0,0],[0,0,0,0]]
    pub fn parents(&self) -> Vec<Self> {
        let depth = self.depth();
        let mut parent = self.0;
        let mut parents = Vec::with_capacity(depth);

        for i in (0..depth).rev() {
            parent[i] = 0;
            parents.push(SubIndex(parent));
        }

        parents
    }

    /// Trim tailing zeros of sub_index and concat with other sub_index. For example,
    /// let sub_index = [3,2,0,0,0,0,0,0];
    /// let other = [4,1,0,0,0,0,0,0];
    /// sub_index.concat(other) = [3,2,4,1,0,0,0,0];
    pub fn concat(&self, other: &SubIndex) -> Self {
        // Trim trailing zeros of both operands, so that unused limbs do not
        // count towards the resulting depth (and cannot silently truncate a
        // non-zero limb).
        let mut this = self.to_trimmed_vec();
        this.extend(other.to_trimmed_vec());

        assert!(
            this.len() <= N_LIMBS,
            "sub_index depth {} exceeds the maximum supported depth {}",
            this.len(),
            N_LIMBS
        );

        let mut result = [0; N_LIMBS];
        for (i, &val) in this.iter().enumerate() {
            result[i] = val;
        }

        SubIndex(result)
    }

    pub fn push(&mut self, element: u16) {
        // Find the first zero element to replace
        if let Some(position) = self.0.iter().position(|&x| x == 0) {
            self.0[position] = element;
        } else {
            panic!(
                "sub_index is full: it already holds the maximum supported depth of {}",
                N_LIMBS
            );
        }
    }

    pub fn insert(&mut self, index: usize, element: u16) {
        assert!(index < N_LIMBS, "Index out of bounds");

        // Shift elements to the right, starting from the last element to the index
        for i in (index..N_LIMBS - 1).rev() {
            self.0[i + 1] = self.0[i];
        }

        self.0[index] = element;
    }

    pub fn remove(&mut self, index: usize) -> u16 {
        assert!(index < N_LIMBS, "Index out of bounds");
        let removed_element = self.0[index];

        // Shift elements to the left
        for i in index..N_LIMBS - 1 {
            self.0[i] = self.0[i + 1];
        }

        self.0[N_LIMBS - 1] = 0;
        removed_element
    }

    pub fn to_vec(&self) -> Vec<u16> {
        self.0.to_vec()
    }

    /// Remove trailing zeros until no zero left at the tail.
    /// Return empty vec if all zeros.
    pub fn to_trimmed_vec(&self) -> Vec<u16> {
        let mut vec = self.0.to_vec();

        while let Some(v) = vec.pop() {
            if v != 0 {
                vec.push(v);
                break;
            }
        }
        vec
    }
}

impl From<Vec<usize>> for SubIndex {
    fn from(value: Vec<usize>) -> Self {
        Self::new(value)
    }
}
impl From<&Vec<usize>> for SubIndex {
    fn from(value: &Vec<usize>) -> Self {
        Self::new(value.clone())
    }
}
/// Convert SubIndex into u128 in little endian order
impl From<SubIndex> for u128 {
    fn from(sub_index: SubIndex) -> u128 {
        let mut result = 0u128;
        for (i, &value) in sub_index.0.iter().enumerate() {
            result |= (value as u128) << (i * 16);
        }
        result
    }
}

impl From<SubIndex> for u64 {
    fn from(sub_index: SubIndex) -> u64 {
        let value: u128 = sub_index.into();
        value as u64
    }
}

impl From<u128> for SubIndex {
    fn from(value: u128) -> Self {
        debug_assert_eq!(
            value >> (N_LIMBS * N_BITS_ONE_LIMB),
            0,
            "sub_index value exceeds the maximum encoded size"
        );
        let mut result = [0u16; N_LIMBS];

        for (i, r) in result.iter_mut().enumerate() {
            *r = ((value >> (i * 16)) & 0xFFFF) as u16;
        }

        SubIndex(result)
    }
}

impl From<u64> for SubIndex {
    fn from(value: u64) -> Self {
        SubIndex::from(value as u128)
    }
}

impl<F: Field> Scalar<F> for SubIndex {
    fn scalar(&self) -> F {
        from_limbs::value::<F, N_BITS_ONE_LIMB>(
            &self.to_vec().iter().map(|v| *v as u64).collect::<Vec<_>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_roundtrip() {
        let sub = SubIndex::new(vec![1, 2, 3, 4]);
        let value: u64 = sub.clone().into();
        assert_eq!(value, 1 | (2 << 16) | (3 << 32) | (4 << 48));
        assert_eq!(SubIndex::from(value), sub);
    }

    #[test]
    fn concat_trims_trailing_zeros() {
        let a = SubIndex::new(vec![3, 2]);
        let b = SubIndex::new(vec![4, 1]);
        assert_eq!(a.concat(&b).to_vec(), vec![3, 2, 4, 1]);
    }

    #[test]
    fn depth_and_parents() {
        let sub = SubIndex::new(vec![1, 2]);
        assert_eq!(sub.depth(), 2);
        assert_eq!(
            sub.parents(),
            vec![SubIndex::new(vec![1]), SubIndex::default()]
        );
    }

    #[test]
    #[should_panic(expected = "exceeds the maximum supported depth")]
    fn new_rejects_too_many_dimensions() {
        let _ = SubIndex::new(vec![1, 2, 3, 4, 5]);
    }

    #[test]
    #[should_panic(expected = "exceeds the maximum supported depth")]
    fn concat_rejects_depth_overflow() {
        let a = SubIndex::new(vec![1, 2, 3, 4]);
        let _ = a.concat(&SubIndex::new(vec![5]));
    }
}
