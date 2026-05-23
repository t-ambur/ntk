#[cfg(not(windows))]
use std::time::{Duration};

use crate::util;
use crate::commands;
use crate::error::NtkError;

/// Runs through most of the other subcommands in one big function to determine if a remote target is reachable from here
pub async fn run(input_str: &str, web_lookup_mac: bool, ignore_certs: bool, http: bool) -> Result<(), NtkError> {
    #[cfg(all(not(unix), not(feature = "with-libpcap")))]
    println!("WARNING: This command is being ran without libpcap on a non-unix operating system. Very limited output will be available. Please install the libpcap binary and dependencies.");

    // Assert we have a valid IPv4 address (converting from hostname using DNS if needed)
    let target_ip = util::str_or_hostname_to_ipv4(input_str).await;
    let ip_str = target_ip.to_string();
    println!("Running analyze against IP: '{}'", &ip_str);

    // // //
    // L1: Compute which interface will be used for this IP
    // // //
    println!("\nL1:");

    let (source_ip, interface) = util::get_interface_for_target_netdev(&ip_str);

    let source_mac = match interface.mac_addr {
        Some(address) => { address.to_string() }
        None => { String::from("Unknown") }
    };

    let source_network = interface.ipv4.iter()
    .find(|net| net.addr() == source_ip)
    .expect("Could not find matching source network (subnet) on source interface");

    println!("Origin interface is '{}' with MAC '{}' and IP '{}' with prefix '/{}'",
    interface.name, source_mac, source_ip, source_network.prefix_len());
    if let Some(friendly_name) = &interface.friendly_name {
        println!("Windows friendly name: '{}'", friendly_name);
    }

    if interface.is_up() {
        println!("Origin Interface is 'UP'");
    } else {
        println!("Origin Interface is 'DOWN' - ERROR: Subsequent analysis will likely fail!")
    }
    // End L1
    // // //

    // // //
    // L2: Attempt to determine the target MAC Address
    // // //
    #[cfg(any(unix, feature = "with-libpcap"))]
    {
        println!("\nL2:");

        if source_network.contains(&target_ip) {
            println!("Target IP is located in the same subnet as the origin IP. Performing ARP request...");

            // println!("DEBUG: Interfaces: {:?}", pnet::datalink::interfaces());

            #[cfg(not(windows))]
            let pnet_interface = pnet::datalink::interfaces()
            .into_iter()
            .find(|i| i.name == interface.name)
            .expect("Could not find matching pnet interface by name");

            #[cfg(windows)]
            let pnet_interface = pnet::datalink::interfaces()
            .into_iter()
            .find(|i| i.name.contains(&interface.name))
            .expect("Could not find matching pnet interface by substring");

            match commands::discover::resolve_mac_for_ip(&pnet_interface, source_ip, target_ip, Duration::from_secs(10)) {
                Ok(mac) => {
                    println!("Target IP has MAC address: '{}'", mac);
                    if web_lookup_mac {
                        print!("Vendor lookup result (HTTP): ");
                        let _ = commands::fetch::run_get_mac_vendor(&mac.to_string(), ignore_certs).await;
                    }
                }
                Err(NtkError::ArpResolutionTimeout(_)) => {
                    eprintln!("Failed to discover the MAC addresses of the target IP: '{}'!", &ip_str);
                }
                Err(e) => {
                    eprintln!("ARP request failed: {e}");
                }
            }
        } else {
            println!("Target IP is not on the same subnet as the origin IP. An ARP scan will not reveal the MAC address of this machine.");
        }
    }
    // End L2
    // // //

    // // //
    // L3: Ping the target, including a trace of the route
    // // //
    println!("\nL3:");
    if source_network.contains(&target_ip) {
        println!("Target IP is: '{}/{}'", &ip_str, source_network.prefix_len());
    } else {
        println!("Target IP is: '{}'", &ip_str);
    }
    
    #[cfg(any(unix, feature = "with-libpcap"))]
    {
        println!("Pinging: '{}'...", &ip_str);
        if let Err(e) = commands::ping::run_ping(&ip_str, 30, 1, 30).await {
            eprintln!("Failed to ping: {e}");
        }

        println!("\nTracing route to: '{}' ...", &ip_str);
        if let Err(e) = commands::ping::run_traceroute(&ip_str, 10, 10, true).await {
            eprintln!("Failed to traceroute: {e}");
        }
    }

    // End L3
    // // //

    // // //
    // L4: 
    // // //
    println!("\nL4:");
    #[cfg(any(unix, feature = "with-libpcap"))]
    {
        println!("Performing TCP SYN probe of: '{}' ...", &ip_str);
        if let Err(e) = commands::scan::run_tcp_syn_probe(
            &ip_str,
            true,
            10,
            None,
            None,
            10,
            false,
            None
        )
        .await {
            eprintln!("Failed to perform TCP SYN probe: {e}");
        }
    }
    #[cfg(all(not(unix), not(feature = "with-libpcap")))]
    {
        println!("Performing TCP Handshake scan of: '{} ...", &ip_str);
        if let Err(e) = commands::scan_full_handshake::run_tcp_handshake(
            target_ip,
            true,
            10,
            None,
            None
        )
        .await {
            eprintln!("Failed to perform TCP Handshake scan: {e}");
        }
    }
    // End L4
    // // //

    // // //
    // L7:
    // // //
    println!("\nL7:");

    println!("Performing DNS lookup of: '{}'...", &ip_str);
    
    match commands::lookup::run_lookup_addr(target_ip, true).await {
        Ok(_) => {}
        Err(e) => { eprintln!("Failed to perform DNS lookup: {e}"); }
    }

    let full_url = format!("{}://{}", if http { "http" } else { "https" }, ip_str);

    println!("\nPerforming HTTP fetch --no-content redirect test against '{}' ...", &full_url);
    if let Err(e) = commands::fetch::run_fetch(
        &full_url,
        ignore_certs,
        false,
        true,
        None,
        10,
        http
    )
    .await {
        eprintln!("Failed to peform HTTP GET request (is port 443 open?): {e}");
    }
    // End L7
    // // //

    Ok(())
}