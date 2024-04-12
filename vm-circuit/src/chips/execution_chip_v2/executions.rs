pub mod br_bool;
pub mod ld;

pub use br_bool::*;
pub use ld::*;
use strum_macros::EnumIter;

#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq, EnumIter)]
pub enum ExecutionState {
    BrTrue,
    BrFalse,
    Stop,
    Nop,
}
