extern crate netdev;
use netdev::{get_default_interface, get_default_gateway};

use crate::error::NtkError;

/// Gets the default gateway 'ip route' string from the operating system.
///   Can optionally only show the gateway IP Addresses or just the origin interface.
pub async fn run(first_match: bool, gateways_only: bool, interface_only: bool) -> Result<String, NtkError> {
    if gateways_only {
        match get_default_gateway() {
            Ok(default_gw) => {
                if first_match {
                    println!("{}", default_gw.ipv4[0]);
                    Ok(default_gw.ipv4[0].to_string())
                } else {
                    let ip_string = format!("{:?}", default_gw.ipv4);
                    println!("{}", &ip_string);
                    Ok(ip_string)
                }
            }
            Err(s) => { return Err(NtkError::NetDevGatewayFailure(s)) }
        }
    } else if interface_only {
        match get_default_interface() {
            Ok(default_if) => { println!("{}", default_if.name); Ok(default_if.name) }
            Err(s) => { return Err(NtkError::NetDevDefaultInterfaceFailure(s)) }
        }
    } else {
        let default_if_name = match get_default_interface() {
            Ok(default_if) => { default_if.name }
            Err(s) => { return Err(NtkError::NetDevDefaultInterfaceFailure(s)) }
        };
        let default_gw = match get_default_gateway() {
            Ok(gw) => { gw }
            Err(s) => { return Err(NtkError::NetDevGatewayFailure(s)) }
        };
        if first_match {
            let message = format!("'{}' routes to: '{}'", default_if_name, default_gw.ipv4[0]);
            println!("{message}");
            Ok(message)
        } else {
            let message = format!("'{}' routes to: '{:?}'", default_if_name, default_gw.ipv4);
            println!("{message}");
            Ok(message)
        }
    }
}