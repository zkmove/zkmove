use clap::{Parser, Subcommand};
use env_logger::Env;
use log::info;
use zkmove_cli::{aptos_cmds::AptosCommands, poseidon_cmds::PoseidonCommand, vm_cmds::VmCommands};

#[derive(Parser)]
#[command(name = "zkmove", about = "CLI for zkMove")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Vm(VmCommands),
    Aptos(AptosCommands),
    Poseidon(PoseidonCommand),
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Starting zkMove CLI...");
    let args = Cli::parse();

    match args.command {
        Commands::Vm(vm_command) => vm_command.run(),
        Commands::Aptos(aptos_command) => aptos_command.run(),
        Commands::Poseidon(poseidon_command) => poseidon_command.run(),
    }
}
