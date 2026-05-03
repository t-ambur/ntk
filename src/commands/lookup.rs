extern crate dns_lookup;

use std::net::{IpAddr, Ipv4Addr};
use crate::error::NtkError;

pub async fn run_lookup_addr(ip: Ipv4Addr) -> Result<String, NtkError> {
    match dns_lookup::lookup_addr(&ip.into()) {
        Ok(addr) => { println!("{addr}"); Ok(addr) }
        Err(e) => { Err(NtkError::DnsLookup(e)) }
    }
}

pub async fn hostname_to_ips(host: &str) -> Result<Vec<IpAddr>, NtkError> {
    match dns_lookup::lookup_host(host) {
        Ok(ips) => {
            Ok(ips.collect::<Vec<IpAddr>>())
        }
        Err(e) => { Err(NtkError::DnsResolve(e)) }
    }
}

pub async fn run_lookup_host(host: &str) -> Result<Vec<IpAddr>, NtkError> {
    let ips = hostname_to_ips(host).await?;
    for ip in &ips {
        println!("{ip}");
    }
    Ok(ips)
}