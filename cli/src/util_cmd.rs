use crate::to_ark::IntoArk;
use ark_serialize::CanonicalSerialize;
use clap::Subcommand;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::halo2curves::group::GroupEncoding;
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use clap::Parser;

#[derive(Parser)]
pub struct UtilCommand {
    #[command(subcommand)]
    command: UtilCommands,
}

#[derive(Subcommand)]
pub enum UtilCommands {
    ViewParamInfo,
}

impl UtilCommand {
    pub fn run(&self, params: &ParamsKZG<Bn256>) -> anyhow::Result<()> {
        match &self.command {
            UtilCommands::ViewParamInfo => {
                let g = params.get_g().first().unwrap();
                let g2 = params.g2();
                let s_g2 = params.s_g2();

                println!("param info:");
                println!(
                    "halo2 encoding, \nk: {} \ng: {} \ng2: {} \ns_g2: {}\n",
                    params.k(),
                    hex::encode(g.to_bytes()),
                    hex::encode(g2.to_bytes()),
                    hex::encode(s_g2.to_bytes())
                );

                let g = g.to_ark();
                let mut g_bytes = vec![];
                CanonicalSerialize::serialize_compressed(&g, &mut g_bytes).unwrap();
                let g2 = g2.to_ark();
                let mut g2_bytes = vec![];
                CanonicalSerialize::serialize_compressed(&g2, &mut g2_bytes).unwrap();
                let s_g2 = s_g2.to_ark();
                let mut s_g2_bytes = vec![];
                CanonicalSerialize::serialize_compressed(&s_g2, &mut s_g2_bytes).unwrap();
                println!(
                    "arkworks encoding, \nk: {} \ng: {} \ng2: {} \ns_g2: {}\n",
                    params.k(),
                    hex::encode(g_bytes),
                    hex::encode(g2_bytes),
                    hex::encode(s_g2_bytes)
                );
            }
        }
        Ok(())
    }
}
