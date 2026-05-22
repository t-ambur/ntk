use crate::error::NtkError;
use crate::util;

#[cfg(feature = "with-libpcap")]
use pcap::{Capture, Device};

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fmt::Display;

fn get_timestamp() -> String {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");
    let seconds = current_time.as_secs();
    let ms = current_time.subsec_millis();
    format!("{:02}:{:02}:{:02}.{:03}", seconds / 3600 % 24, seconds / 60 % 60, seconds % 60, ms)
}

enum ProtocolType {
    Icmp { type_str: &'static str, id: u16, seq: u16 },
    Igmp { type_str: &'static str, group: Ipv4Addr },
    Tcp  { src_port: u16, dst_port: u16, flags: String },
    Udp  { src_port: u16, dst_port: u16 },
    Other(u8),
}

fn format_and_print(
    protocol_name: impl Display,
    src_ip: impl Display,
    dst_ip: impl Display,
    protocol_subtype: impl Display,
    length: Option<u16>,
    extra_info: impl Display
) {
    let len_str = length.map_or(String::new(), |l| format!("len: {}  ", l));
    println!(
        "{}|  {:<4} {:<22}  {:<21} => {:<21} {}{}",
        get_timestamp(),
        protocol_name,
        protocol_subtype,
        src_ip,
        dst_ip,
        len_str,
        extra_info
    );
}

struct PacketSummary {
    src_ip:   Ipv4Addr,
    dst_ip:   Ipv4Addr,
    protocol: ProtocolType,
    length:   u16,
}
impl PacketSummary {
    fn println(&self) {
        match &self.protocol {
            ProtocolType::Icmp { type_str, id, seq } => {
                format_and_print(
                    "ICMP",
                    self.src_ip,
                    self.dst_ip,
                    type_str,
                    Some(self.length),
                    format!("id={id} seq={seq}")
                );
            },
            ProtocolType::Igmp { type_str, group } => {
                format_and_print(
                    "IGMP",
                    self.src_ip,
                    self.dst_ip,
                    type_str,
                    Some(self.length),
                    format!("group={group}")
                )
            },
            ProtocolType::Tcp { src_port, dst_port, flags } => {
                format_and_print(
                    "TCP",
                    format!("{}:{}", self.src_ip, src_port),
                    format!("{}:{}", self.dst_ip, dst_port),
                    flags,
                    Some(self.length),
                    ""
                )
            },
            ProtocolType::Udp { src_port, dst_port } => {
                format_and_print(
                    "UDP",
                    format!("{}:{}", self.src_ip, src_port),
                    format!("{}:{}", self.dst_ip, dst_port),
                    "",
                    Some(self.length),
                    ""
                )
            },
            ProtocolType::Other(p) => {
                format_and_print(
                    p,
                    self.src_ip,
                    self.dst_ip,
                    "",
                    Some(self.length),
                    ""
                )
            },
        }
    }
}

struct ArpSummary {
    op_str:     &'static str,
    sender_mac: [u8; 6],
    sender_ip:  Ipv4Addr,
    target_mac: [u8; 6],
    target_ip:  Ipv4Addr,
}
impl ArpSummary {
    fn println(&self) {
        let fmt_mac = |m: &[u8; 6]| format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        format_and_print(
            "ARP",
            self.sender_ip,
            self.target_ip,
            self.op_str,
            None,
            format!("MAC: {} => {}", fmt_mac(&self.sender_mac), fmt_mac(&self.target_mac))
        );
    }
}

// ── Link-layer frame offset ───────────────────────────────────────────────────

// pcap gives us the raw link-layer frame. The offset to the IP header depends
// on the datalink type reported by the capture handle.
//
// DLT_EN10MB (Ethernet) — the common case on macOS and Windows physical NICs:
//   6 dst MAC + 6 src MAC + 2 EtherType = 14 bytes
//
// DLT_NULL (loopback on macOS) — 4-byte BSD loopback header, value 2 = AF_INET
//
// We check cap.get_datalink() once before the loop rather than branching per packet.
#[cfg(feature = "with-libpcap")]
enum Datalink {
    Ethernet,   // 14-byte Ethernet header
    BsdLoopback, // 4-byte BSD loopback header (macOS lo0)
}

#[cfg(feature = "with-libpcap")]
fn detect_datalink(cap: &Capture<pcap::Active>) -> Datalink {
    match cap.get_datalink() {
        pcap::Linktype(0)  => Datalink::BsdLoopback, // DLT_NULL
        _                  => Datalink::Ethernet,     // DLT_EN10MB and fallback
    }
}

#[cfg(feature = "with-libpcap")]
fn ip_offset(frame: &[u8], dl: &Datalink) -> Option<(usize, u16)> {
    match dl {
        Datalink::Ethernet => {
            if frame.len() < 14 { return None; }
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            Some((14, ethertype))
        }
        Datalink::BsdLoopback => {
            if frame.len() < 4 { return None; }
            let af = u32::from_ne_bytes([frame[0], frame[1], frame[2], frame[3]]);
            // Loopback only carries IP — no ARP possible here
            if af == 2 { Some((4, 0x0800)) } else { None }
        }
    }
}


// ── Parsing ──────────────────────────────────────────────────────────────────

fn parse_ipv4(buf: &[u8]) -> Option<PacketSummary> {
    if buf.len() < 20 { return None; }
    let ihl      = ((buf[0] & 0x0f) as usize) * 4;
    let length   = u16::from_be_bytes([buf[2], buf[3]]);
    let _ttl      = buf[8];
    let protocol = buf[9];
    let src_ip   = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst_ip   = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    if buf.len() < ihl { return None; }
    let payload = &buf[ihl..];
    let proto = match protocol {
        1  => parse_icmp(payload),
        2  => parse_igmp(payload),
        6  => parse_tcp(payload),
        17 => parse_udp(payload),
        n  => ProtocolType::Other(n),
    };
    Some(PacketSummary { src_ip, dst_ip, protocol: proto, length,  })
}

fn parse_igmp(buf: &[u8]) -> ProtocolType {
    if buf.len() < 8 { return ProtocolType::Igmp { type_str: "IGMP (short)", group: Ipv4Addr::UNSPECIFIED }; }
    let type_str = igmp_type_str(buf[0]);
    let group    = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    ProtocolType::Igmp { type_str, group }
}

fn igmp_type_str(t: u8) -> &'static str {
    match t {
        0x11 => "Membership Query",
        0x12 => "Membership Report v1",
        0x16 => "Membership Report v2",
        0x22 => "Membership Report v3",
        0x17 => "Leave Group",
        _    => "IGMP (other)",
    }
}

fn parse_arp(buf: &[u8]) -> Option<ArpSummary> {
    // htype(2) + ptype(2) + hlen(1) + plen(1) + oper(2)
    // + sender_mac(6) + sender_ip(4) + target_mac(6) + target_ip(4) = 28 bytes
    if buf.len() < 28 { return None; }
    let htype = u16::from_be_bytes([buf[0], buf[1]]);
    let ptype = u16::from_be_bytes([buf[2], buf[3]]);
    if htype != 1 || ptype != 0x0800 { return None; } // Ethernet + IPv4 only
    let op = match u16::from_be_bytes([buf[6], buf[7]]) {
        1 => "Request",
        2 => "Reply",
        _ => "Unknown",
    };
    let sender_mac: [u8; 6] = buf[8..14].try_into().unwrap();
    let sender_ip  = Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]);
    let target_mac: [u8; 6] = buf[18..24].try_into().unwrap();
    let target_ip  = Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]);
    Some(ArpSummary { op_str: op, sender_mac, sender_ip, target_mac, target_ip })
}

fn parse_icmp(buf: &[u8]) -> ProtocolType {
    if buf.len() < 8 { return ProtocolType::Icmp { type_str: "ICMP (short)", id: 0, seq: 0 }; }
    let type_str = icmp_type_str(buf[0], buf[1]);
    let id  = u16::from_be_bytes([buf[4], buf[5]]);
    let seq = u16::from_be_bytes([buf[6], buf[7]]);
    ProtocolType::Icmp { type_str, id, seq }
}

fn icmp_type_str(t: u8, code: u8) -> &'static str {
    match (t, code) {
        (0,  0) => "Echo Reply",
        (8,  0) => "Echo Request",
        (11, 0) => "TTL Exceeded",
        (11, 1) => "Frag Reassembly Exceeded",
        (3,  0) => "Net Unreachable",
        (3,  1) => "Host Unreachable",
        (3,  2) => "Proto Unreachable",
        (3,  3) => "Port Unreachable",
        (3,  4) => "Fragmentation Needed",
        _       => "ICMP (other)",
    }
}

fn parse_tcp(buf: &[u8]) -> ProtocolType {
    if buf.len() < 20 { return ProtocolType::Tcp { src_port: 0, dst_port: 0, flags: "?".into() }; }
    ProtocolType::Tcp {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        flags:    tcp_flags_str(buf[13]),
    }
}

fn tcp_flags_str(f: u8) -> String {
    let mut p = Vec::new();
    if f & 0x02 != 0 { p.push("SYN"); }
    if f & 0x10 != 0 { p.push("ACK"); }
    if f & 0x01 != 0 { p.push("FIN"); }
    if f & 0x04 != 0 { p.push("RST"); }
    if f & 0x08 != 0 { p.push("PSH"); }
    if f & 0x20 != 0 { p.push("URG"); }
    if p.is_empty() { "NONE".into() } else { p.join("+") }
}

fn parse_udp(buf: &[u8]) -> ProtocolType {
    if buf.len() < 8 { return ProtocolType::Udp { src_port: 0, dst_port: 0 }; }
    ProtocolType::Udp {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
    }
}

#[cfg(feature = "with-libpcap")]
pub async fn run(interface_name: &str) -> Result<(), NtkError> {
    let pcap_device = util::find_pcap_device_by_name(interface_name)?;

    let mut cap = Capture::from_device(pcap_device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .promisc(true)    // promiscuous — see everything on the wire
        .snaplen(65535)   // full packet
        .timeout(1000)    // ms; lets Ctrl-C be responsive
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    let dl = detect_datalink(&cap);

    // filtering could be implemented with cap.filter("icmp", true)

    println!("Listening on '{}' ...", interface_name);

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some((offset, ethertype)) = ip_offset(packet.data, &dl) {
                    let payload = &packet.data[offset..];
                    match ethertype {
                        0x0800 => { if let Some(pkt) = parse_ipv4(payload) { pkt.println(); } }
                        0x0806 => { if let Some(arp) = parse_arp(payload)  { arp.println(); } }
                        _      => {}
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(NtkError::LibPacketCaptureFailure(e)),
        }
    }
}

#[cfg(not(feature = "with-libpcap"))]
pub async fn run(interface_name: &str) -> Result<(), NtkError> {
    println!("NOT IMPLEMENTED");
    Ok(())
}
