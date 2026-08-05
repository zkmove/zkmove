use super::Version;
use value_type::sub_index::SubIndex;
use value_type::word::Word;

#[derive(Default, Clone, Debug)]
pub struct MemoryOp(
    pub Option<StackPop>,
    pub Option<StackPush>,
    pub Option<LocalReadWrite>,
);

#[derive(Clone, Debug)]
pub struct StackPop {
    pub index: u16,
    pub sub_index: SubIndex,
    pub value: Word,
    pub value_header: bool,
    pub version: u64,
}

#[derive(Clone, Debug)]
pub struct StackPush {
    pub index: u16,
    pub sub_index: SubIndex,
    pub value: Word,
    pub value_header: bool,
    pub version: u64,
}

#[derive(Clone, Debug)]
pub struct LocalReadWrite {
    pub frame_index: u16,
    pub index: u8,
    pub sub_index: SubIndex,
    pub read_value: Word,
    pub read_value_header: bool,
    pub read_value_invalid: bool,
    pub read_version: u64,
    pub write_value: Word,
    pub write_value_header: bool,
    pub write_value_invalid: bool,
    pub write_version: u64,
}

impl LocalReadWrite {
    pub fn new(
        frame_index: u16,
        local_index: u8,
        sub_index: SubIndex,
        old_slot: Slot,
        new_slot: Slot,
    ) -> Self {
        LocalReadWrite {
            frame_index,
            index: local_index,
            sub_index,
            read_value: old_slot.value,
            read_value_header: old_slot.value_header,
            read_value_invalid: old_slot.value_invalid,
            read_version: old_slot.version,
            write_value: new_slot.value,
            write_value_header: new_slot.value_header,
            write_value_invalid: new_slot.value_invalid,
            write_version: new_slot.version,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub value: Word,
    pub value_header: bool,
    pub value_invalid: bool,
    pub version: u64,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            value: Word::default(),
            value_header: false,
            value_invalid: true,
            version: 1,
        }
    }
}

impl Slot {
    pub fn with_version(mut self, version: Version) -> Self {
        debug_assert!(version > self.version);
        self.version = version;
        self
    }
}
