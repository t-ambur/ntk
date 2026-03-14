use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ntk")]
#[command(author = "Trevor Amburgey")]
#[command(version = "0.1.0")]
#[command(about = "Network Toolkit - Cross-platform network diagnostics")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Discover devices on the local network
    Discover {
        /// Network interface to use (e.g., eth0, wlan0)
        #[arg(short, long, required = true)]
        interface: String,
        
        /// Target subnet (e.g., 192.168.1.0/24)
        #[arg(short, long, default_value = "auto")]
        subnet: String,
    }
}