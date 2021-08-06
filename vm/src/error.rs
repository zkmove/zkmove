use std::result::Result;

pub type VmResult<T> = Result<T, RuntimeError>;

#[derive(Debug)]
pub enum StatusCode {
    StackUnderflow,
    StackOverflow,
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
}
