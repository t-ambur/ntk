mod cli;
mod commands;
mod error;
mod util;
mod scan_util;

use error::NtkError;
use cli::{Cli, Commands};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), NtkError> {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

/// This function nests inside main instead of being main.
/// This is done to better handle the error code and message returned from the subcommand ran.
/// (If an error occurs).
async fn run() -> Result<(), NtkError> {
    let cli = Cli::parse();

    #[cfg(any(unix, feature = "with-libpcap"))]
    match cli.command {
        Commands::Analyze { ip, web_lookup_mac , ignore_certs, use_http} => {
            commands::analyze::run(&ip, web_lookup_mac, ignore_certs, use_http).await?
        },
        Commands::Banner { ip } => {
            commands::banner::run(util::str_to_ip(&ip)).await?
        }
        Commands::Discover { interface , collection_time} => {
            commands::discover::run(interface, collection_time).await?
        },
        Commands::Fetch { url, ignore_certs, use_http, download, show_headers, no_content, download_path, num_hops } => {
            if download {
                commands::fetch::run_download(&url, ignore_certs, show_headers, download_path, use_http).await?
            } else {
                commands::fetch::run_fetch(&url, ignore_certs, show_headers, no_content, download_path, num_hops, use_http).await?
            }  
        },
        Commands::Gateway { first_match, gateways_only, interface_only } => {
            commands::gateway::run(first_match, gateways_only, interface_only).await?;
        },
        Commands::Interface { down_only, up_only} => {
            commands::interface::run(down_only, up_only).await?;
        },
        Commands::Lookup { ip , name_lookup} => {
            if name_lookup {
                commands::lookup::run_lookup_host(&ip, true).await?;
            } else {
                commands::lookup::run_lookup_addr(util::str_to_ip(&ip), true).await?;
            }
        },
        Commands::MacVendor { address, ignore_certs } => {
            commands::fetch::run_get_mac_vendor(&address, ignore_certs).await?
        },
        Commands::Ping {ip, trace, count, packet_ttl, timeout, lookup_trace_hostnames} => {
            if trace {
                commands::ping::run_traceroute(&ip, timeout, packet_ttl, lookup_trace_hostnames).await?
            } else {
                commands::ping::run_ping(&ip, timeout, count, packet_ttl).await?
            }
        },
        Commands::Scan { ip, lookup_name, delay, start_range, end_range, timeout, ack_probe, fin_probe, full_handshake, reset, source_port } => {
            if full_handshake {
                commands::scan_full_handshake::run_tcp_handshake(util::str_to_ip(&ip), lookup_name, delay, start_range, end_range).await?
            } else {
                {
                    if ack_probe || fin_probe {
                        commands::scan::run_tcp_ack_probe(&ip, lookup_name, delay, start_range, end_range, timeout, source_port, fin_probe).await?
                    } else {
                        commands::scan::run_tcp_syn_probe(&ip, lookup_name, delay, start_range, end_range, timeout, reset, source_port).await?
                    }
                }
            }
        },
        Commands::View { interface } => {
            commands::view::run(&interface).await?;
        }
    }

    #[cfg(all(not(unix), not(feature = "with-libpcap")))]
    match cli.command {
        Commands::Analyze { ip, web_lookup_mac , ignore_certs, use_http} => {
            commands::analyze::run(&ip, web_lookup_mac, ignore_certs, use_http).await?
        },
        Commands::Banner { ip } => {
            commands::banner::run(util::str_to_ip(&ip)).await?
        }
        Commands::Discover { interface: _ , collection_time: _ } => {
            return Err(
                NtkError::WrongBinaryInUse(
                    String::from(
                        "The Discover command requires a 'libpcap' equivalent when not ran on a Unix host (e.g. Npcap on Windows). Please install the dependency and use the appropriate ntk binary."
                    )
                )
            );
        },
        Commands::Fetch { url, ignore_certs, use_http, download, show_headers, no_content, download_path, num_hops } => {
            if download {
                commands::fetch::run_download(&url, ignore_certs, show_headers, download_path, use_http).await?
            } else {
                commands::fetch::run_fetch(&url, ignore_certs, show_headers, no_content, download_path, num_hops, use_http).await?
            }  
        },
        Commands::Gateway { first_match, gateways_only, interface_only } => {
            commands::gateway::run(first_match, gateways_only, interface_only).await?;
        },
        Commands::Interface { down_only, up_only} => {
            commands::interface::run(down_only, up_only).await?;
        },
        Commands::Lookup { ip , name_lookup} => {
            if name_lookup {
                commands::lookup::run_lookup_host(&ip, true).await?;
            } else {
                commands::lookup::run_lookup_addr(util::str_to_ip(&ip), true).await?;
            }
        },
        Commands::MacVendor { address, ignore_certs } => {
            commands::fetch::run_get_mac_vendor(&address, ignore_certs).await?
        },
        Commands::Ping {ip: _, trace: _, count: _, packet_ttl: _, timeout: _, lookup_trace_hostnames: _ } => {
            return Err(
                NtkError::WrongBinaryInUse(
                    String::from(
                        "The Ping command requires a 'libpcap' equivalent when not ran on a Unix host (e.g. Npcap on Windows). Please install the dependency and use the appropriate ntk binary."
                    )
                )
            );
            
        },
        Commands::Scan { ip, lookup_name, delay, start_range, end_range, timeout: _, ack_probe: _, fin_probe: _, full_handshake, reset: _, source_port: _ } => {
            if full_handshake {
                commands::scan_full_handshake::run_tcp_handshake(util::str_to_ip(&ip), lookup_name, delay, start_range, end_range).await?
            } else {
                return Err(
                    NtkError::WrongBinaryInUse(
                        String::from(
                            "The SYN, ACK, and FIN probes require a 'libpcap' equivalent when not ran on a Unix host (e.g. Npcap on Windows). Please install the dependency and use the appropriate ntk binary. Alternatively, use the '-f' flag to init a full handshake."
                        )
                    )
                );
            }
        },
        Commands::View { interface: _ } => {
            return Err(
                NtkError::WrongBinaryInUse(
                    String::from(
                        "The view subcommand requires a 'libpcap' equivalent when not ran on a Unix host (e.g. Npcap on Windows). Please install the dependency and use the appropriate ntk binary."
                    )
                )
            );
        }
    }
    
    Ok(())
}