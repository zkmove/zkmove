use std::result::Result;

pub type VmResult<T> = Result<T, RuntimeError>;

#[derive(Debug)]
pub enum StatusCode {
    StackUnderflow,
    StackOverflow,
    ValueConversionError,
    SynthesisError,
    ScriptLoadingError,
    CopyLocalError,
    StoreLocalError,
    MoveLocalError,
    OutOfBounds,
    UnsupportedBytecode,
    MoveAbort,
}

#[derive(Debug)]
pub struct RuntimeError {
    status: StatusCode,
    message: Option<String>,
}

impl RuntimeError {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            message: None,
        }
    }
    pub fn with_message(self, message: String) -> Self {
        Self {
            status: self.status,
            message: Some(message),
        }
    }
}
