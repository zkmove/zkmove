use clap::{Parser, Subcommand};
use env_logger::Env;
use log::info;
#[cfg(feature = "verifier")]
use zkmove_cli::commands::{AptosCommands, SuiCommands};
use zkmove_cli::commands::{PoseidonCommand, VmCommands};

#[derive(Parser)]
#[command(name = "zkmove", about = "CLI for zkMove")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Vm(VmCommands),
    #[cfg(feature = "verifier")]
    Aptos(AptosCommands),
    #[cfg(feature = "verifier")]
    Sui(SuiCommands),
    Poseidon(PoseidonCommand),
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Starting zkMove CLI...");
    let args = Cli::parse();

    match args.command {
        Commands::Vm(vm_command) => vm_command.run(),
        #[cfg(feature = "verifier")]
        Commands::Aptos(aptos_command) => aptos_command.run(),
        #[cfg(feature = "verifier")]
        Commands::Sui(sui_command) => sui_command.run(),
        Commands::Poseidon(poseidon_command) => poseidon_command.run(),
    }
}
