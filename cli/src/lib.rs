#![feature(path_file_prefix)]

use clap::ValueEnum;

// Copyright (c) zkMove Authors
pub mod aptos_cmds;
pub mod poseidon_cmds;
pub mod vm_cmds;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KZGVariant {
    GWC,
    SHPLONK,
}
