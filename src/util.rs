use crate::commands::lookup;

use std::{net::{IpAddr, Ipv4Addr}, str::FromStr};

#[cfg(any(unix, feature = "with-libpcap"))]
use std::collections::HashMap;

#[cfg(feature = "with-libpcap")]
use pnet::packet::{Packet, ethernet::{EtherTypes, EthernetPacket}, icmp::{IcmpPacket, IcmpTypes, echo_reply::EchoReplyPacket}, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket};
#[cfg(feature = "with-libpcap")]
use pcap::Device;
#[cfg(feature = "with-libpcap")]
use crate::error::NtkError;

use netdev::get_interfaces;

/// Asserts a string is a valid IPv4 addresses and then converts it to the core::net type
pub fn str_to_ip(s: &str) -> Ipv4Addr {
    assert_is_valid_ipv4(&s);
    Ipv4Addr::from_str(s).expect("Failed to convert String slice into IPv4Addr despite asserting 'is valid IPv4'.")
}

/// Returns true or false if string is a valid IPv4 addresses
pub fn is_valid_ipv4(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok()
}

/// Asserts a string is a valid IPv4 addresses.
/// Panics if the string is not valid.
pub fn assert_is_valid_ipv4(s: &str) {
    if !is_valid_ipv4(s) {
        panic!("Provided String is not a valid IPv4 address!: {s}");
    }
}

/// Takes in a string that is supposed to represent a hostname.
/// Performs a DNS lookup of that hostname to resolve an IPv4 Address for it.
/// Panics if: only IPv6 addresses are returned or if unable to perform the lookup or the string is an invalid IPv4 string.
pub async fn str_or_hostname_to_ipv4(ip_str: &str) -> Ipv4Addr {
    let ip = match is_valid_ipv4(ip_str) {
        true => { str_to_ip(ip_str) }
        false => {
            let ips = lookup::hostname_to_ips(ip_str).await.unwrap_or_else(|err| panic!("Was unable to parse provided String {ip_str} into an IPv4 address! Please provide a valid IPv4 address to ping! Error: {err}"));
            ips.into_iter()
            .find_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .unwrap_or_else(|| panic!("Was unable to parse provided String {ip_str} into an IPv4 address! Please provide a valid IPv4 address to ping!"))
        }
    };
    ip
}

/// Converts a string to the MAC Address OCI (vendor/manfacturer information)
/// A MAC Address OCI is the first three octets.
pub fn parse_to_mac_oci(input: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = input.split(':').collect();

    if parts.len() < 3 || parts.len() > 6 {
        return None;
    }

    let mut bytes = Vec::new();

    for part in parts {
        if part.len() != 2 {
            return None;
        }

        match u8::from_str_radix(part, 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return None,
        }
    }

    Some(bytes)
}

/// Asserts a string is a valid MAC Address OCI.
/// A MAC Address OCI is at least the first three octets
pub fn assert_valid_mac_oci(input: &str) {
    parse_to_mac_oci(input)
        .unwrap_or_else(|| panic!("Invalid MAC/OCI format!: '{}' ... You must include at least the first three octets of a MAC Address (e.g. FF:FF:FF).", input));
}

/// Ask the OS what IP we should have for the route to the host.
/// This is done by attempting to bind to a socket as if we were going to use it- then dropping the bind.
/// The Drop implementation in rust will automatically drop the socket when the function goes out of scope.
pub fn compute_source_ip(ip_str: &str) -> IpAddr {
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            socket.connect((ip_str, 1)).expect("Was unable to connect to the socket to determine the source IP for the TCP request");
            match socket.local_addr() {
                Ok(a) => {a.ip() }
                Err(e) => { panic!("Was unable to retrieve the local address to use a TCP IP source!: {e}") }
            }
        }
        Err(e) => { panic!("Was unable to bind to the host in order to determine the source IP!: {e}") }
    }
}

/// Parses a TCP reply from the pcap crate
#[cfg(feature = "with-libpcap")]
pub fn parse_tcp_reply(data: &[u8]) -> Option<(u16, u8)> {
    let eth = EthernetPacket::new(data)?;

    // Only handle IPv4 for now; extend with IPv6 as needed.
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(eth.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let tcp = TcpPacket::new(ipv4.payload())?;
    Some((tcp.get_source(), tcp.get_flags()))
}

/// Gets the 'device' (interface) from which to capture packet responses on (by IPv4)
#[cfg(feature = "with-libpcap")]
pub fn find_pcap_device(source_ip: Ipv4Addr) -> Result<Device, NtkError> {
    let devices = Device::list()
        .or_else(|e| Err(NtkError::LibPacketCaptureFailure(e)))?;
    for dev in &devices {
        for addr in &dev.addresses {
            if let std::net::IpAddr::V4(v4) = addr.addr {
                if v4 == source_ip {
                    return Ok(dev.clone());
                }
            }
        }
    }
    return Err(NtkError::IpIfAssociationError(source_ip.to_string()));
}

// /// Gets the 'device' (interface) from which to capture packet responses on (by name)
// #[cfg(feature = "with-libpcap")]
// pub fn find_pcap_device_by_name(interface_name: &str) -> Result<Device, NtkError> {
//     Device::list()
//         .map_err(NtkError::LibPacketCaptureFailure)?
//         .into_iter()
//         .find(|device| device.name == interface_name)
//         .ok_or_else(|| NtkError::IfNameNotFound(String::from(interface_name)))
// }

/// The parsed result of an inbound ICMP packet, covering both ping and traceroute use cases.
#[cfg(feature = "with-libpcap")]
pub enum IcmpResponse {
    /// Final hop: destination sent an EchoReply.
    EchoReply { seq: u16, src: IpAddr },
    /// Intermediate hop: a router sent TimeExceeded, embedding the original
    /// ICMP header so we can recover the sequence number.
    TimeExceeded { seq: u16, src: IpAddr },
}

/// Parses an raw Ethernet frame into an [`IcmpResponse`].
/// Returns `None` if the frame isn't an ICMP echo-reply or time-exceeded
/// packet, or if any layer fails to parse.
#[cfg(feature = "with-libpcap")]
pub fn parse_icmp_packet(data: &[u8]) -> Option<IcmpResponse> {
    // Ethernet → IPv4
    let eth = EthernetPacket::new(data)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ipv4 = Ipv4Packet::new(eth.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return None;
    }

    let src = IpAddr::V4(ipv4.get_source());
    let icmp = IcmpPacket::new(ipv4.payload())?;

    match icmp.get_icmp_type() {
        IcmpTypes::EchoReply => {
            let reply = EchoReplyPacket::new(icmp.packet())?;
            Some(IcmpResponse::EchoReply { seq: reply.get_sequence_number(), src })
        }

        IcmpTypes::TimeExceeded => {
            // TimeExceeded payload: 4 bytes unused, then the original IP header,
            // then the first 8 bytes of the original ICMP (type, code, checksum,
            // identifier, sequence). We need to skip past the outer ICMP header
            // (4 bytes type/code/checksum + 4 bytes unused = 8 bytes) to reach
            // the embedded IP header.
            let payload = icmp.payload(); // starts after the 4-byte ICMP header
                                          // [0..3]  = unused (4 bytes)
                                          // [4..]   = original IP header + 8 bytes ICMP
            let inner_ip = Ipv4Packet::new(&payload[4..])?;
            let _inner_ip_len = (inner_ip.get_header_length() as usize) * 4;

            // The original ICMP header sits immediately after the inner IP header
            let inner_icmp_bytes = inner_ip.payload();
            if inner_icmp_bytes.len() < 8 {
                return None;
            }
            // Bytes 6-7 of an ICMP echo header are the sequence number (big-endian)
            let seq = u16::from_be_bytes([inner_icmp_bytes[6], inner_icmp_bytes[7]]);

            Some(IcmpResponse::TimeExceeded { seq, src })
        }

        _ => None,
    }
}

/// Grabs an interface object from the netdev crate (not pnet).
/// The netdev crate is typically more cross platform friendly.
pub fn get_interface_for_target_netdev(target: &str) -> (Ipv4Addr, netdev::Interface) {
    let source_ip = compute_source_ip(target);
    let ipv4 = match source_ip {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => panic!("Expected IPv4 address but received IPv6 when getting source/origin interface"),
    };

    let interface = get_interfaces()
        .into_iter()
        .find(|iface| iface.ipv4.iter().any(|net| net.addr() == ipv4))
        .expect("Could not match source IP to a network interface");

    (ipv4, interface)
}

#[cfg(any(unix, feature = "with-libpcap"))]
fn normalize_interface_name(name: &str) -> &str {
    name.strip_prefix(r"\Device\NPF_").unwrap_or(name)
}
#[cfg(any(unix, feature = "with-libpcap"))]
fn interface_name_matches(stored: &str, query: &str) -> bool {
    stored == query || normalize_interface_name(stored) == query || stored == normalize_interface_name(query)
}

#[cfg(any(unix, feature = "with-libpcap"))]
pub struct NetdevInterfaceNameMap {
    by_friendly: HashMap<String,  String>,
    by_interface: HashMap<String, String>,
}
#[cfg(any(unix, feature = "with-libpcap"))]
impl NetdevInterfaceNameMap {
    pub fn build() -> Self {
        let mut by_friendly = HashMap::new();
        let mut by_interface = HashMap::new();

        for interface in get_interfaces() {
            let name = normalize_interface_name(&interface.name).to_string();
            let friendly = interface.friendly_name.unwrap_or_else(|| name.clone());
            by_friendly.insert(friendly.clone(), name.clone());
            by_interface.insert(name, friendly);
        }

        Self { by_friendly, by_interface }
    }
    // pub fn interface_by_friendly(&self, friendly: &str) -> Option<String> {
    //     self.by_friendly.get(friendly).cloned()
    // }
    // pub fn friendly_by_interface(&self, interface_name: &str) -> Option<String> {
    //     self.by_interface.get(interface_name).cloned()
    // }
    fn resolve_name(&self, query: &str) -> Option<String> {
        let norm_query = normalize_interface_name(query);

        // 1. exact friendly name match (try both forms)
        if let Some(name) = self.by_friendly.get(query)
            .or_else(|| self.by_friendly.get(norm_query))
        {
            return Some(name.clone());
        }
        // 2. exact interface name match (try both forms)
        if self.by_interface.contains_key(query) {
            return Some(query.to_string());
        }
        if self.by_interface.contains_key(norm_query) {
            return Some(norm_query.to_string());
        }
        // 3. substring match on interface name (try both forms)
        self.by_interface
            .iter()
            .find(|(iface, _)| iface.contains(query) || iface.contains(norm_query))
            .map(|(iface, _)| iface.clone())
    }
    // pub fn resolve_netdev(&self, query: &str) -> Option<netdev::Interface> {
    //     let name = self.resolve_name(query)?;
    //     get_interfaces()
    //         .into_iter()
    //         .find(|i| interface_name_matches(&i.name, &name))
    // }
    #[cfg(all(not(feature = "with-libpcap"), not(windows)))]
    pub fn resolve_pnet(&self, query: &str) -> Option<pnet::datalink::NetworkInterface> {
        let name = self.resolve_name(query)?;
        pnet::datalink::interfaces()
            .into_iter()
            .find(|i| interface_name_matches(&i.name, &name))
    }
    #[cfg(feature = "with-libpcap")]
    pub fn resolve_pcap(&self, query: &str) -> Option<Device> {
        let name = self.resolve_name(query)?;
        Device::list().ok()?
            .into_iter()
            .find(|d| interface_name_matches(&d.name, &name))
    }
}

/// Function on windows to retrieve a friendly name from a GUID interface
#[cfg(windows)]
pub fn get_netdev_friendly_name(pnet_name: &str) -> String {
    let upper = pnet_name.to_ascii_uppercase();
    get_interfaces()
        .into_iter()
        .find(|nd_if| {
            upper.contains(&nd_if.name.to_ascii_uppercase())
        })
        .and_then(|nd_if| nd_if.friendly_name)
        .unwrap_or(String::from("Unknown"))
}

/// Creates a println stdout message with the words DEBUG: in front only if verbose mode is true
macro_rules! debug {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            println!("DEBUG: {}", format_args!($($arg)*));
        }
    };
}
pub(crate) use debug;

// // //

// Old code - for reference only

// /// Convenience wrapper retained for ping, which only cares about EchoReply.
// #[cfg(feature = "with-libpcap")]
// pub fn parse_icmp_reply(data: &[u8]) -> Option<(u16, IpAddr)> {
//     match parse_icmp_packet(data)? {
//         IcmpResponse::EchoReply { seq, src } => Some((seq, src)),
//         _ => None,
//     }
// }

// #[cfg(feature = "with-libpcap")]
// pub fn get_interface_for_target_libpcap(target: &str) -> (Ipv4Addr, pnet::datalink::NetworkInterface) {
//     let source_ip = compute_source_ip(target);
//     let ipv4 = match source_ip {
//         IpAddr::V4(addr) => addr,
//         IpAddr::V6(_) => panic!("Expected IPv4 address but received IPv6 when getting source/origin interface"),
//     };
    
//     let interface= pnet::datalink::interfaces()
//         .into_iter()
//         .find(|iface| iface.ips.iter().any(|ip| ip.ip() == source_ip))
//         .expect("Could not match source IP to a network interface");

//     (ipv4, interface)
// }