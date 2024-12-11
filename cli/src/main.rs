use clap::{Parser, Subcommand};
use logger::error;
use std::process::exit;
use zkmove_cli::aptos_cmds::AptosCommands;
use zkmove_cli::prove_cmd::RunCommand;

#[derive(Parser)]
#[command(name = "zkmove", about = "CLI for zkMove")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Run the full sequence of setup, proving, and verification")]
    Run(RunCommand),
    #[command(about = "Aptos-related commands")]
    Aptos(AptosCommands),
}

fn main() {
    let args = Cli::parse();

    let result = match args.command {
        Commands::Run(run_command) => run_command.run(),
        Commands::Aptos(aptos_command) => aptos_command.run(),
    };

    if let Err(error) = result {
        error!("{}", error);
        exit(1);
    }
}
