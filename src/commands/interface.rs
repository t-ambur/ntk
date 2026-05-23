extern crate netdev;
use netdev::{get_interfaces, Interface};

use crate::error::NtkError;

/// Shows all interfaces on this device.
/// Can optionally show only the ones that are in the DOWN or UP states.
pub async fn run(down_only: bool, up_only: bool) -> Result<Vec<Interface>, NtkError> {
    let mut interfaces = get_interfaces();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    let default_col_width: usize = 16;

    for iface in &interfaces {
        let status = if iface.is_up() { "UP" } else { "DOWN" };

        if down_only && status == "UP"   { continue; }
        if up_only  && status == "DOWN" { continue; }

        let mac = match iface.mac_addr {
            Some(m) => m.to_string(),
            None    => String::from("Unknown"),
        };

        // On Windows, devices are identified via
        // 'friendly names' for users and GUIDs otherwise
        // Mac apparently tags some common interfaces with friendly_name as well
        // We print both because its confusing otherwise
        match &iface.friendly_name {
            Some(friendly_name) => {
                #[cfg(windows)]
                println!("\n {}", friendly_name);
                #[cfg(not(windows))]
                println!(" {}", friendly_name);
                print!(
                    "{:<name_w$} {:<s_w$} {:<m_w$} ",
                    iface.name, status, mac,
                    name_w = 10,
                    s_w    = 5,
                    m_w    = default_col_width,
                );
            }
            None => {
                print!(
                    "{:<name_w$} {:<s_w$} {:<m_w$} ",
                    iface.name, status, mac,
                    name_w = 10,
                    s_w    = 5,
                    m_w    = default_col_width,
                );
            }
        }

        for ip_net in &iface.ipv4 {
            // ip_net is netdev::ip::Ipv4Net, which has .addr and .prefix_len
            print!(
                " {:<ip_w$} ",
                format!("{}", ip_net),
                ip_w = 18,
            );
        }
        println!();
    }

    Ok(interfaces)
}


// // // // // // // // // // // // // // // //

// Older code using pnet
// This is less cross-platform friendly
// use pnet::datalink::{self, NetworkInterface};

// use crate::error::NtkError;

// pub async fn run(down_only: bool , up_only: bool) -> Result<Vec<NetworkInterface>, NtkError> {
//     let interfaces = datalink::interfaces();
//     let default_col_width: usize = 16;

//     for interface in &interfaces {
//         let mut status = String::from("DOWN");
//         if interface.is_up() { status = String::from("UP"); }
        
//         if down_only && status == "UP" { continue; }
//         if up_only && status == "DOWN" { continue; }

//         let mac_address = match interface.mac {
//             Some(m) => { m.to_string() }
//             None => { String::from("Unknown") }
//         };

//         print!("{:<name_w$} {:<s_w$} {:<m_w$} ", interface.name, status, mac_address, name_w = 10, s_w = 5, m_w = default_col_width);

//         for ip_network in &interface.ips {
//             if ip_network.is_ipv4() {
//                 print!(" {:<ip_w$} ", format!("{}/{}", ip_network.ip().to_string(), ip_network.prefix()), ip_w = 18);
//             }
//         }
//         println!();
//     }

//     Ok(interfaces)
// }