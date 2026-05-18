extern crate dns_lookup;

use std::net::{IpAddr, Ipv4Addr};
use crate::error::NtkError;

/// Uses the dns_lookup crate to discover a hostname from a provided IP Address
pub async fn run_lookup_addr(ip: Ipv4Addr, should_print: bool) -> Result<String, NtkError> {
    match dns_lookup::lookup_addr(&ip.into()) {
        Ok(addr) => { 
            if should_print {
                println!("{addr}");
            }
            Ok(addr)
        }
        Err(e) => { Err(NtkError::DnsLookup(e)) }
    }
}

/// Uses the dns_lookup crate to return one or more IP Addresses from a provided hostname.
pub async fn hostname_to_ips(host: &str) -> Result<Vec<IpAddr>, NtkError> {
    match dns_lookup::lookup_host(host) {
        Ok(ips) => {
            Ok(ips.collect::<Vec<IpAddr>>())
        }
        Err(e) => { Err(NtkError::DnsResolve(e)) }
    }
}

/// Prints out each of the IP Addresses assigned to a hostname.
/// Invokes 'hostname_to_ips' to use the dns_lookup crate on the hostname
pub async fn run_lookup_host(host: &str, should_print: bool) -> Result<Vec<IpAddr>, NtkError> {
    let ips = hostname_to_ips(host).await?;
    if should_print {
        for ip in &ips {
            println!("{ip}");
        }
    }
    Ok(ips)
}
