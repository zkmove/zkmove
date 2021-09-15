use bellman::SynthesisError;
use std::result::Result;

pub type VmResult<T> = Result<T, RuntimeError>;

#[derive(Debug)]
pub enum StatusCode {
    StackUnderflow,
    StackOverflow,
    ValueConversionError,
    SynthesisError(SynthesisError),
    ScriptLoadingError,
    CopyLocalError,
    StoreLocalError,
    MoveLocalError,
    OutOfBounds,
    UnsupportedBytecode,
    MoveAbort,
    UnsupportedMoveType,
    TypeMissMatch,
    ArithmeticError,
    ModuleNotFound,
}

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
    pub fn status_code(&self) -> &StatusCode {
        &self.status
    }
    pub fn message(&self) -> Option<String> {
        self.message.clone()
    }
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}, {}",
            self.status,
            self.message()
                .unwrap_or_else(|| "with no message".to_string())
        )
    }
}

impl std::fmt::Debug for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?}, {}",
            self.status,
            self.message()
                .unwrap_or_else(|| "with no message".to_string())
        )
    }
}

impl std::error::Error for RuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
