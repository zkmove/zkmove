
use serde::Serialize;

#[derive(Serialize)]
pub struct ArgWithTypeJSON {
    pub arg_type: String,
    pub value: serde_json::Value,
}

#[derive(Serialize)]
pub struct EntryFunctionArgumentsJSON {
    pub function_id: String,
    pub type_args: Vec<String>,
    pub args: Vec<ArgWithTypeJSON>,
}

#[derive(Serialize)]
pub struct HexEncodedBytes(pub Vec<u8>);

impl ToString for HexEncodedBytes {
    fn to_string(&self) -> String {
        format!("0x{}", hex::encode(&self.0))
    }
} 