// Copyright (c) zkMove Authors

use anyhow::{anyhow, Error, Result};
use movelang::argument::{parse_type_tags, ScriptArguments, Signer};
use movelang::value::TypeTag;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

// directives can be added to move source files to tell vm how to run the test.
// currently we support several directives. For example,
//
// //! mods: arith.move - import a module
// //! signer: 0x1      - only for test, set signer as 0x1
// //! args: 0, 1       - pass arguments to the script, multiple args should separate with comma
// //! circuit: vm      - specify which circuit to use (vm or fast, default to support both)
// //! step_max_row        - fix the row of execution steps
// //! stack_ops_num    - fix the number of stack ops
// //! locals_ops_num   - fix the number of locals ops

#[derive(Debug)]
pub enum Circuit {
    FastCircuit,
    VmCircuit,
}

#[derive(Debug)]
pub struct RunConfig {
    pub signer: Option<Signer>,
    pub args: Option<ScriptArguments>,
    pub new_args: Option<ScriptArguments>,
    pub ty_args: Vec<TypeTag>,
    pub new_ty_args: Vec<TypeTag>,
    pub modules: Vec<String>,
    pub circuit: Option<Circuit>,
    pub step_max_row: Option<usize>,
    pub stack_ops_num: Option<usize>,
    pub locals_ops_num: Option<usize>,
    pub global_ops_num: Option<usize>,
}

impl RunConfig {
    pub fn new(script_file: &Path) -> Result<RunConfig> {
        let mut config = RunConfig {
            signer: None,
            args: None,
            ty_args: vec![],
            new_args: None,
            new_ty_args: vec![],
            modules: vec![],
            circuit: None,
            step_max_row: None,
            stack_ops_num: None,
            locals_ops_num: None,
            global_ops_num: None,
        };
        let file_str = script_file.to_str().expect("path is None.");

        let mut f = File::open(script_file)
            .map_err(|err| std::io::Error::new(err.kind(), format!("{}: {}", err, file_str)))?;
        let mut buffer = String::new();
        f.read_to_string(&mut buffer)?;

        for line in buffer.lines() {
            let s = line.split_whitespace().collect::<String>();
            if let Some(s) = s.strip_prefix("//!signer:") {
                config.signer = Some(s.parse::<Signer>()?);
            }
            if let Some(s) = s.strip_prefix("//!args:") {
                config.args = Some(s.parse::<ScriptArguments>()?);
            }
            if let Some(s) = s.strip_prefix("//!new_args:") {
                config.new_args = Some(s.parse()?);
            }
            if let Some(s) = s.strip_prefix("//!ty_args:") {
                config.ty_args = parse_type_tags(s)?;
            }
            if let Some(s) = s.strip_prefix("//!new_ty_args:") {
                config.new_ty_args = parse_type_tags(s)?;
            }
            if let Some(s) = s.strip_prefix("//!mods:") {
                config.modules.push(s.to_string()); //todo: support multiple modules
            }
            if let Some(s) = s.strip_prefix("//!circuit:") {
                config.circuit = Some(s.parse::<Circuit>()?);
            }
            if let Some(s) = s.strip_prefix("//!step_max_row:") {
                config.step_max_row = Some(s.parse::<usize>()?);
            }
            if let Some(s) = s.strip_prefix("//!stack_ops_num:") {
                config.stack_ops_num = Some(s.parse::<usize>()?);
            }
            if let Some(s) = s.strip_prefix("//!locals_ops_num:") {
                config.locals_ops_num = Some(s.parse::<usize>()?);
            }
            if let Some(s) = s.strip_prefix("//!global_ops_num:") {
                config.global_ops_num = Some(s.parse::<usize>()?);
            }
        }
        Ok(config)
    }
}

impl FromStr for Circuit {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        match input {
            "fast" => Ok(Circuit::FastCircuit),
            "vm" => Ok(Circuit::VmCircuit),
            _ => Err(anyhow!("Wrong circuit type. Should be fast or vm.")),
        }
    }
}
