mod cli;
mod commands;

use cli::{Cli, Commands};
use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let result = match cli.command {
        Commands::Discover { interface, subnet } => {
            commands::discover::run(&interface, &subnet);
        }
    };
    
    Ok(())
}