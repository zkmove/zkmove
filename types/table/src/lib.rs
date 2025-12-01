use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
/// Each item represents the lookup table to query
pub enum Table {
    /// The range check table for 4-bits
    Nibble,
    /// The range check table for u8
    U8,
    /// The range check table for 2-bits
    U2,
    /// The range check table for u16
    #[cfg(feature = "table-u16")]
    U16,
    /// The rest of the fixed table. See [`FixedTableTag`]
    Fixed,
    /// Lookup for bytecode table
    Bytecode,
    /// Lookup for constant table
    Constant,
    /// Lookup for function
    Function,
    /// Pow of 2
    Pow2,
    /// Bitwise lookup
    Bitwise,
    /// Poseidon hash lookup
    PoseidonHash,
}
