use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket,};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use std::{net::IpAddr, net::Ipv4Addr};
use std::time::{Duration, Instant};

use crate::error::NtkError;

#[cfg(windows)]
use crate::util::get_netdev_friendly_name;

#[cfg(any(windows, target_os = "macos"))]
use netdev::get_interfaces;

/// Function to get the network interface by name or default to the first available one
fn get_interface(interface_name: &str) -> Result<NetworkInterface, NtkError> {
    // Get all available network interfaces
    let interfaces = datalink::interfaces();

    // On Windows and Mac, try to resolve the interface name using the friendly name first
    // then fallback to the GUID
    #[cfg(any(windows, target_os = "macos"))]
    {
        let netdev_name = get_interfaces()
            .into_iter()
            .find(|nd_if| {
                nd_if.friendly_name.as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(interface_name))
            })
            .map(|nd_if| nd_if.name);

        if let Some(interface) = interfaces.into_iter().find(|iface| {
            netdev_name
                .as_deref()
                .is_some_and(|n| iface.name.contains(n))
                || iface.name.contains(interface_name)
        }) {
            return Ok(interface);
        }
    }

    // If an interface name is provided, try to find it
    #[cfg(all(not(windows), not(target_os = "macos")))]
    if let Some(interface) = interfaces.into_iter().find(|iface| iface.name == interface_name) {
        return Ok(interface);
    }

    Err(NtkError::IfNameNotFound(String::from(interface_name)))
}

/// Runs an ARP scan against either all interfaces or the specified interface name
pub async fn run(interface_name: Option<String>, collection_time: u64) -> Result<(), NtkError> {
    match interface_name {
        Some(n) => {
            let ifname = match get_interface(&n) {
                Ok(i) => { i }
                Err(e) => { return Err(e) }
            };
            return scan_interface(ifname, collection_time).await
        }
        None => {
            println!("Scanning all interfaces because --interface was not provided");
            let interfaces = datalink::interfaces();
            
            for interface in interfaces {
                let lc_interface_name = interface.name.to_lowercase();
                if lc_interface_name.eq("lo") || 
                    lc_interface_name.eq("lo0") ||
                    lc_interface_name.starts_with("loopback")
                {
                    println!("Skipping loopback interface: {}", interface.name);
                    continue;
                }
                match scan_interface(interface, collection_time).await {
                    Err(e) => { eprintln!("Failed to scan interface: {e}"); }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Scans a specific pnet NetworkInterface using ARP
pub async fn scan_interface(interface: NetworkInterface, collection_time: u64) -> Result<(), NtkError> {
    // Set up the network interface
    let interface_name = interface.name.clone();
    let source_mac = match interface.mac {
        Some(mac) => { mac }
        None => { return Err(NtkError::SourceMacAddressFailure(interface_name)) }
    };
    let source_ip_network = match interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4()) {
            Some(n) => { n }
            None => {
                return Err(NtkError::IfNameHasNoAssignedIps(interface_name));
            }
        };
    let source_ip: Ipv4Addr = match source_ip_network.ip() {
        IpAddr::V4(ipv4) => ipv4,
        IpAddr::V6(_) => {
            return Err(NtkError::IfNameHasNoAssignedIps(interface_name));
        },
    };

    let prefix = source_ip_network.prefix();

    if prefix <= 0 {
        #[cfg(windows)]
        println!("Interface: '{}' : '{}' ... Will not be discovered as network prefix is less than or equal to zero.", get_netdev_friendly_name(&interface.name), interface_name.strip_prefix(r"\Device\NPF_").unwrap_or(&interface_name));
        #[cfg(not(windows))]
        println!("Interface: '{}' ... Will not be discovered as network prefix is less than or equal to zero.", interface_name);
        return Ok(())
    } else if prefix >= 32 {
        #[cfg(windows)]
        println!("Interface: '{}' : '{}' ...Will not be discovered as network prefix is greater than or equal to 32.", get_netdev_friendly_name(&interface.name), interface_name.strip_prefix(r"\Device\NPF_").unwrap_or(&interface_name));
        #[cfg(not(windows))]
        println!("Interface: '{}' ... Will not be discovered as network prefix is greater than or equal to 32.", interface_name);
        return Ok(())
    }
    
    #[cfg(windows)]
    println!("[*] Discovering devices on Interface: '{}' : '{}' ...",  get_netdev_friendly_name(&interface.name), interface_name.strip_prefix(r"\Device\NPF_").unwrap_or(&interface_name));
    #[cfg(not(windows))]
    println!("[*] Discovering devices on Interface: '{}' ...", interface_name);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(NtkError::DatalinkUnsupportedChannel),
        Err(e) => return Err(NtkError::DatalinkOpenFailure(e)),
    };

    // Send ARP requests to all hosts in the subnet
    for ip in source_ip_network.iter() {
        if let IpAddr::V4(ipv4) = ip {
            match send_arp_request(&mut tx, source_mac, source_ip, ipv4) {
                Ok(()) => {}
                Err(e) => return Err(e)
            }
        } else {
            return Err(NtkError::Ipv6FoundError)
        }
    }

    // Start the timer to wait for ARP replies
    let start = Instant::now();

    // Format the output with column widths
    let col_width: usize = 16;
    println!("{:<ip_w$} {:<m_w$}", "IP", "MAC", ip_w = col_width, m_w = col_width);

    // Collect ARP replies
    while start.elapsed() < Duration::from_secs(collection_time) {
        if let Ok(packet) = rx.next() {
            if let Some((ip, mac)) = parse_arp_reply(packet) {
                // println!("{} {}", ip, mac);
                println!("{:<ip_w$} {:<m_w$}", ip, mac, ip_w = col_width, m_w = col_width);
            }
        }
    }
    
    #[cfg(windows)]
    println!("[*] Discovery complete for '{}' : '{}'", get_netdev_friendly_name(&interface.name), interface_name.strip_prefix(r"\Device\NPF_").unwrap_or(&interface_name));
    #[cfg(not(windows))]
    println!("[*] Discovery complete for {interface_name}");
    Ok(())
}

/// Function to send an ARP request
pub fn send_arp_request(
    tx: &mut Box<dyn datalink::DataLinkSender>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<(), NtkError> {
    // Ensure the buffer is exactly the size we expect
    // The buffer is esentially 'the packet itself'
    // The code below "builds"/inserts into the buffer
    // Then we send it out
    const ETHERNET_HEADER_SIZE: usize = 14;
    const ARP_DATA_SIZE: usize = 28;
    const PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + ARP_DATA_SIZE;
    let mut buffer = [0u8; PACKET_SIZE];

    // Create the Ethernet packet header
    let mut ethernet = MutableEthernetPacket::new(&mut buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;
    ethernet.set_destination(MacAddr::broadcast());
    ethernet.set_source(source_mac);
    ethernet.set_ethertype(EtherTypes::Arp);

    // Create the ARP packet
    // We have to be careful to create the ARP data
    // AFTER the ethernet header (created above)
    // Create a mutable slice reference to the buffer
    let arp_buffer = &mut buffer[ETHERNET_HEADER_SIZE..];
    let mut arp = MutableArpPacket::new(arp_buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;

    // Set the ARP packet parameters
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(source_mac);
    arp.set_sender_proto_addr(source_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);

    // Send the ARP request
    // Its okay for dst to be None
    // We specify broadcast in the ethernet header
    tx.send_to(&buffer, None);
    Ok(())
}

/// Function to parse an ARP reply and return the sender's IP and MAC address
pub fn parse_arp_reply(packet: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let ethernet = EthernetPacket::new(packet)?;

    if ethernet.get_ethertype() != EtherTypes::Arp {
        return None;
    }

    let arp = ArpPacket::new(ethernet.payload())?;

    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

/// Sends a single ARP request on `pnet_interface` for `target_ip` and waits
/// up to `timeout` for a reply. Returns the target's MAC address, or
/// `NtkError::ArpResolutionTimeout` if no reply arrives in time.
#[cfg(any(unix, feature = "with-libpcap"))]
pub fn resolve_mac_for_ip(
    pnet_interface: &NetworkInterface,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<MacAddr, NtkError> {
    let source_mac = pnet_interface.mac
        .ok_or(NtkError::SourceMacAddressFailure(pnet_interface.name.clone()))?;

    let (mut tx, mut rx) = match datalink::channel(pnet_interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(NtkError::DatalinkUnsupportedChannel),
        Err(e) => return Err(NtkError::DatalinkOpenFailure(e)),
    };

    send_arp_request(&mut tx, source_mac, source_ip, target_ip)?;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some((ip, mac)) = parse_arp_reply(packet) {
                    if ip == target_ip {
                        return Ok(mac);
                    }
                }
            }
            Err(e) => return Err(NtkError::DatalinkOpenFailure(e)),
        }
    }

    Err(NtkError::ArpResolutionTimeout(target_ip.to_string()))
}
