use anyhow::Result;
use clap::Parser;
use halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField};
use log::info;
use move_core_types::u256::U256;

const DOMAIN_SPEC: u64 = 1; // Domain spec for Poseidon hash

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
        let hash_result = poseidon_base::Hashable::hash_with_domain(
            [Fr::from_u128(self.value), Fr::from_u128(nonce)],
            Fr::from(DOMAIN_SPEC),
        );
        let hash_val = U256::from_le_bytes(&hash_result.to_repr().as_ref().try_into()?);
        info!(
            "Poseidon hash of value {} with nonce {}: 0x{:x}",
            self.value, nonce, hash_val
        );
        Ok(())
    }
}
