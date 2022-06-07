// Copyright (c) zkMove Authors

use anyhow::{anyhow, Error, Result};
use movelang::argument::ScriptArguments;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

// directives can be added to move source files to tell vm how to run the test.
// currently we support three kinds of directives: mods, args and circuit. For example,
//
// //! mods: arith.move - import a module
// //! args: 0, 1       - pass arguments to the script, multiple args should separate with comma
// //! circuit: vm      - specify which circuit to use (vm or fast, default to support both)
// //! steps_num        - fix the number of execution steps
// //! stack_ops_num    - fix the number of stack ops
// //! locals_ops_num   - fix the number of locals ops

#[derive(Debug)]
pub enum Circuit {
    FastCircuit,
    VmCircuit,
}

#[derive(Debug)]
pub struct RunConfig {
    pub args: Option<ScriptArguments>,
    pub modules: Vec<String>,
    pub circuit: Option<Circuit>,
    pub steps_num: Option<usize>,
    pub stack_ops_num: Option<usize>,
    pub locals_ops_num: Option<usize>,
}

impl RunConfig {
    pub fn new(script_file: &Path) -> Result<RunConfig> {
        let mut config = RunConfig {
            args: None,
            modules: vec![],
            circuit: None,
            steps_num: None,
            stack_ops_num: None,
            locals_ops_num: None,
        };
        let file_str = script_file.to_str().expect("path is None.");

        let mut f = File::open(script_file)
            .map_err(|err| std::io::Error::new(err.kind(), format!("{}: {}", err, file_str)))?;
        let mut buffer = String::new();
        f.read_to_string(&mut buffer)?;

        for line in buffer.lines().into_iter() {
            let s = line.split_whitespace().collect::<String>();
            if let Some(s) = s.strip_prefix("//!args:") {
                config.args = Some(s.parse::<ScriptArguments>()?);
            }
            if let Some(s) = s.strip_prefix("//!mods:") {
                config.modules.push(s.to_string()); //todo: support multiple modules
            }
            if let Some(s) = s.strip_prefix("//!circuit:") {
                config.circuit = Some(s.parse::<Circuit>()?);
            }
            if let Some(s) = s.strip_prefix("//!steps_num:") {
                config.steps_num = Some(s.parse::<usize>()?);
            }
            if let Some(s) = s.strip_prefix("//!stack_ops_num:") {
                config.stack_ops_num = Some(s.parse::<usize>()?);
            }
            if let Some(s) = s.strip_prefix("//!locals_ops_num:") {
                config.locals_ops_num = Some(s.parse::<usize>()?);
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
