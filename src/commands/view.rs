use crate::error::NtkError;
use crate::util;

use pcap::{Capture, Device};

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

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

// TODO format the output better here
struct PacketSummary {
    src_ip:   Ipv4Addr,
    dst_ip:   Ipv4Addr,
    protocol: ProtocolType,
    length:   u16,
}
impl PacketSummary {
    fn println(&self) {
        let ts = get_timestamp();
        match &self.protocol {
            ProtocolType::Icmp { type_str, id, seq } => println!(
                "{ts}|  {:<15}  =>  {:<15}  ICMP  {type_str:<22}  id={id} seq={seq} len={}",
                self.src_ip.to_string(), self.dst_ip.to_string(), self.length
            ),
            ProtocolType::Igmp { type_str, group } => println!(
                "{ts}|  {:<15}  =>  {:<15}  IGMP  {type_str:<22}  group={group} len={}",
                self.src_ip.to_string(), self.dst_ip.to_string(), self.length
            ),
            ProtocolType::Tcp { src_port, dst_port, flags } => println!(
                "{ts}|  {}:{src_port:<5}  =>  {}:{dst_port:<5}  TCP   {flags:<12} len={}",
                self.src_ip, self.dst_ip, self.length
            ),
            ProtocolType::Udp { src_port, dst_port } => println!(
                "{ts}|  {}:{src_port:<5}  =>  {}:{dst_port:<5}  UDP len={}",
                self.src_ip, self.dst_ip, self.length
            ),
            ProtocolType::Other(p) => println!(
                "{ts}|  {:<15}  =>  {:<15}  proto={p} len={}",
                self.src_ip.to_string(), self.dst_ip.to_string(), self.length
            ),
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
        let ts = get_timestamp();
        let fmt_mac = |m: &[u8; 6]| format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        println!(
            "{ts}|  ARP  {}  sender={}({})  target={}({})",
            self.op_str,
            self.sender_ip, fmt_mac(&self.sender_mac),
            self.target_ip, fmt_mac(&self.target_mac),
        );
    }
}

pub async fn run(interface_name: &str) -> Result<(), NtkError> {
    let pcap_device = util::find_pcap_device_by_name(interface_name)?;

    let mut cap = Capture::from_device(pcap_device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .promisc(true)    // promiscuous — see everything on the wire
        .snaplen(65535)   // full packet
        .timeout(1000)    // ms; lets Ctrl-C be responsive
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    // filtering could be implemented with cap.filter("icmp", true)

    println!("Listening on '{}' ...", interface_name);

    Ok(())
}