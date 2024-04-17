pub mod br_bool;

pub use br_bool::*;
use strum_macros::EnumIter;
#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq, EnumIter)]
pub enum ExecutionState {
    BrTrue,
    BrFalse,
    Stop,
    Nop,
}
