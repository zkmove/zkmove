// Copyright (c) zkMove Authors

use crate::ops;
use anyhow::Result;
use clap::Parser;
use log::info;

#[derive(Parser)]
#[command(about = "Utility for poseidon hash")]
pub struct PoseidonCommand {
    #[arg(short = 'v', long = "value", help = "the value to be hashed")]
    value: u128,
    #[arg(
        long = "nonce",
        help = "the nonce for hashing, if not provided, a random nonce will be used"
    )]
    nonce: Option<u128>,
}

impl PoseidonCommand {
    pub fn run(&self) -> Result<()> {
        let nonce = self.nonce.unwrap_or_else(|| {
            // Generate a random nonce if not provided
            use rand::Rng;
            let mut rng = rand::thread_rng();
            rng.gen()
        });

        let hash_val = ops::poseidon::poseidon_hash(self.value, nonce)?;

        info!("Value: {}", self.value);
        info!("Nonce: {}", nonce);
        info!("Poseidon hash (U256): {}", hash_val);
        info!("Poseidon hash (hex): 0x{:x}", hash_val);

        Ok(())
    }
}
