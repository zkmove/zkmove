pub mod br_bool;
pub mod ld;
pub mod borrow_loc;

pub use br_bool::*;
pub use ld::*;
pub use borrow_loc::*;
use strum_macros::EnumIter;

#[derive(Copy, Clone, Debug, PartialEq, Hash, Eq, EnumIter)]
pub enum ExecutionState {
    BrTrue,
    BrFalse,
    Stop,
    Nop,
}
