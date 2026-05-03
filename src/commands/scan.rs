
use crate::error::NtkError;
use crate::util;
use crate::scan_util::{PortIter, port_map};

use pnet::packet::{MutablePacket};
use pnet::packet::tcp::{
    MutableTcpPacket, TcpFlags
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportReceiver;
use pnet::transport::{
    transport_channel,
    TransportSender,
    TransportChannelType::Layer4,
    TransportProtocol::Ipv4
};

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, Duration};

// // WITH libpcap imports // //
#[cfg(feature = "with-libpcap")]
use pcap::{Capture};
// // // //

// // NOT libpcap imports // //
#[cfg(not(feature = "with-libpcap"))]
use pnet::transport::{tcp_packet_iter};
// // // //


const TCP_HEADER_LEN: usize = 20;


// Determines what window size and shift should be spoofed by our probes
fn get_os_tcp_defaults() -> (u16, u8) {
    // Returns (window_size, wscale_shift)
    match std::env::consts::OS {
        "linux"   => (64240, 7),
        "windows" => (65535, 8),
        "macos"   => (65535, 6),
        _         => (65535, 7), // sane fallback
    }
}

// A SYN packet is the initial TCP handshake packet
// You hope to see an SYN and ACK response from an open port
fn send_syn_packet(source_ip: &Ipv4Addr, dest_ip: Ipv4Addr, dest_port: u16, tx: &mut TransportSender, source_port: u16) -> Result<(), NtkError> {
    let mut buffer = [0u8; TCP_HEADER_LEN + 20];
    let mut packet = MutableTcpPacket::new(&mut buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;

    let (window_size, wscale) = get_os_tcp_defaults();
    
    packet.set_source(source_port);
    packet.set_destination(dest_port);
    packet.set_sequence(rand::random());
    packet.set_acknowledgement(0);
    packet.set_flags(TcpFlags::SYN);
    packet.set_data_offset(10);
    packet.set_window(window_size);

    let buf = packet.packet_mut();
    let opts = &mut buf[20..40];
    
    opts.fill(1); // Prefill with NOPs (No Operation) for padding

    // MSS
    opts[0] = 2; // MSS (Max Segment Size) - Kind 2
    opts[1] = 4; // MSS Length (including kind and length)
    opts[2] = 0x05; // High byte
    opts[3] = 0xb4; // Low byte (together equal 1460)

    // SACK Permitted (Selective Acknowledgement)
    opts[4] = 4; // 
    opts[5] = 2; // Length

    // Timestamps
    opts[6] = 8; // Timestamp - Kind 8
    opts[7] = 10; // Timestamp Length

    let tsval: u32 = (std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("Failed to calculate the duration_since the UNIX EPOCH which is quite unusual as that should always be in the past.")
    .as_millis() & 0xFFFF_FFFF) as u32;

    opts[8..12].copy_from_slice(&tsval.to_be_bytes()); // of sender (1 is fine for a scanner)
    opts[12..16].copy_from_slice(&0u32.to_be_bytes()); // echo of tsval rx from other side (tsecr)

    // Window Scale - Kind 3, Length 3, Shift 
    opts[16] = 3;
    opts[17] = 3;
    opts[18] = wscale;

    // Without a correct checksum, routers will drop the packet
    packet.set_checksum(pnet::packet::tcp::ipv4_checksum(&packet.to_immutable(), source_ip, &dest_ip));

    // For debugging, dumping the packet:
    // println!("{:02x?}", packet.packet());
    
    match tx.send_to(packet, dest_ip.into()) {
        Err(e) => { return Err(NtkError::PacketSendFailure(e)) }
        _ => { }
    };
    Ok(())
}

// An ACK probe abuses RFC 793 where a host is supposed to respond with 'RST' to this invalid handshake
// (i.e. a SYN should occur first but doesn't so the host follows protocol and says 'Reset')
// ACK probes are also commonly not blocked when SYN probes are because the firewall assumes by
// default that ACK is for an already established connection
fn send_ack_packet(source_ip: &Ipv4Addr, dest_ip: Ipv4Addr, dest_port: u16, tx: &mut TransportSender, source_port: u16, fin_probe: bool) -> Result<(), NtkError> {
    let mut buffer = [0u8; TCP_HEADER_LEN + 16];
    let mut packet = MutableTcpPacket::new(&mut buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;
    
    let (window_size, wscale) = get_os_tcp_defaults();

    packet.set_source(source_port);
    packet.set_destination(dest_port);
    packet.set_sequence(rand::random());
    packet.set_acknowledgement(rand::random());
    packet.set_data_offset(9);
    packet.set_window(window_size);

    if fin_probe {
        packet.set_flags(TcpFlags::FIN);
    } else {
        packet.set_flags(TcpFlags::ACK);
    }

    let buf = packet.packet_mut();
    let opts = &mut buf[20..36];
    
    opts.fill(1); // Prefill with NOPs (No Operation) for padding

    // Timestamps
    opts[0] = 8; // Timestamp - Kind 8
    opts[1] = 10; // Timestamp Length

    let tsval: u32 = (std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("Failed to calculate the duration_since the UNIX EPOCH which is quite unusual as that should always be in the past.")
    .as_millis() & 0xFFFF_FFFF) as u32;

    opts[2..6].copy_from_slice(&tsval.to_be_bytes()); // of sender (1 is fine for a scanner)
    opts[6..10].copy_from_slice(&0u32.to_be_bytes()); // echo of tsval rx from other side (tsecr)

    // Window Scale - Kind 3, Length 3, Shift 
    opts[10] = 3;
    opts[11] = 3;
    opts[12] = wscale;

    // Without a correct checksum, routers will drop the packet
    packet.set_checksum(pnet::packet::tcp::ipv4_checksum(&packet.to_immutable(), source_ip, &dest_ip));

    match tx.send_to(packet, dest_ip.into()) {
        Err(e) => { return Err(NtkError::PacketSendFailure(e)) }
        _ => { }
    };
    Ok(())
}

// Handles the common transport setup (primarily for sending) between the functions
async fn handle_transport_setup(ip_str: &str,  user_source_port: Option<u16>)
    -> Result<
        (Ipv4Addr, u16, TransportSender, TransportReceiver, Ipv4Addr, Instant),
        NtkError>
    {
    let target_ip = util::str_or_hostname_to_ipv4(ip_str).await;
    let source_port: u16 = match user_source_port {
        Some(p) => { p }
        None => { rand::random_range(32768..61000) }
    };
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (tx, rx) = match transport_channel(65536, protocol) {
        Ok(channels) => channels,
        Err(e) => return Err(NtkError::DatalinkOpenFailure(e)),
    };

    let source_ip = match util::compute_source_ip(&ip_str) {
        IpAddr::V4(ip) => { ip }
        IpAddr::V6(_) => { return Err(NtkError::Ipv6FoundError) }
    };
    let start = Instant::now();
    Ok((target_ip, source_port, tx, rx, source_ip, start))
}

pub async fn run_tcp_syn_probe(ip_str: &str, lookup_name: bool, delay: u64, start_range: Option<u16>, end_range: Option<u16>, timeout_seconds: u8, show_reset: bool, user_source_port: Option<u16>) -> Result<(), NtkError> {
    #[cfg(feature = "with-libpcap")]
    let (target_ip, source_port, mut tx, _rx, source_ip, start)
        = handle_transport_setup(ip_str, user_source_port).await?;
    
    #[cfg(not(feature = "with-libpcap"))]
    let (target_ip, source_port, mut tx, rx, source_ip, start)
        = handle_transport_setup(ip_str, user_source_port).await?;

    let timeout_seconds = timeout_seconds as u64;
    
    #[cfg(feature = "with-libpcap")]
    let deadline = start + Duration::from_secs(timeout_seconds);
    #[cfg(feature = "with-libpcap")]
    let handle = open_capture_thread(source_ip, source_port, target_ip, deadline, show_reset)?;

    #[cfg(not(feature = "with-libpcap"))]
    let _handle = open_capture_thread(rx, start, timeout_seconds, source_port, target_ip, lookup_name, show_reset)?;

    // println!("DEBUG: Sending from: {} on port {} to {}", source_ip, source_port, target_ip);
    for port in PortIter::new(start_range, end_range) {
        // println!("Sending: {}", port);
        match send_syn_packet(&source_ip, target_ip, port, &mut tx, source_port) {
            Ok(()) => {}
            Err(e) => { return Err(e); }
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    #[cfg(feature = "with-libpcap")]
    rx_tcp_packets(timeout_seconds, handle, lookup_name).await?;

    #[cfg(not(feature = "with-libpcap"))]
    tokio::time::sleep(Duration::from_secs(timeout_seconds as u64)).await;
    
    Ok(())
}

pub async fn run_tcp_ack_probe(ip_str: &str, lookup_name: bool, delay: u64, start_range: Option<u16>, end_range: Option<u16>, timeout_seconds: u8, user_source_port: Option<u16>, fin_probe: bool) -> Result<(), NtkError> {
    #[cfg(feature = "with-libpcap")]
    let (target_ip, source_port, mut tx, _rx, source_ip, start)
        = handle_transport_setup(ip_str, user_source_port).await?;
    
    #[cfg(not(feature = "with-libpcap"))]
    let (target_ip, source_port, mut tx, rx, source_ip, start)
        = handle_transport_setup(ip_str, user_source_port).await?;

    let timeout_seconds = timeout_seconds as u64;
    
    #[cfg(feature = "with-libpcap")]
    let deadline = start + Duration::from_secs(timeout_seconds);
    #[cfg(feature = "with-libpcap")]
    let handle = open_capture_thread_ack(source_ip, source_port, target_ip, deadline)?;

    #[cfg(not(feature = "with-libpcap"))]
    let _handle = open_capture_thread_ack(rx, start, timeout_seconds, source_port, target_ip, lookup_name)?;

    // println!("DEBUG: Sending from: {} on port {} to {}", source_ip, source_port, target_ip);
    for port in PortIter::new(start_range, end_range) {
        // println!("Sending: {}", port);
        match send_ack_packet(&source_ip, target_ip, port, &mut tx, source_port, fin_probe) {
            Ok(()) => {}
            Err(e) => { return Err(e); }
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    #[cfg(feature = "with-libpcap")]
    rx_tcp_packets_ack(timeout_seconds, handle, lookup_name).await?;

    #[cfg(not(feature = "with-libpcap"))]
    tokio::time::sleep(Duration::from_secs(timeout_seconds as u64)).await;   

    Ok(())
}

#[cfg(not(feature = "with-libpcap"))]
fn open_capture_thread_ack(
    mut rx: TransportReceiver,
    start: Instant,
    timeout_seconds: u64,
    source_port: u16,
    target_ip: Ipv4Addr,
    lookup_name: bool,
) -> Result<tokio::task::JoinHandle<()>, NtkError> {
     let listener_handle = tokio::spawn(async move {
        let mut iter = tcp_packet_iter(&mut rx);
        while start.elapsed() < Duration::from_secs(timeout_seconds as u64) {
            match iter.next_with_timeout(Duration::from_secs(timeout_seconds as u64)) {
                Ok(Some((packet, addr))) => {
                    let flags = packet.get_flags();
                    if addr == IpAddr::V4(target_ip) && packet.get_destination() == source_port {
                        if flags & TcpFlags::RST == TcpFlags::RST {
                            let discovered_port = packet.get_source();
                            if lookup_name {
                                let common_name: &str = port_map().get(&discovered_port).unwrap_or(&"Unknown");
                                println!("RST: {discovered_port}: {common_name}");
                            } else {
                                println!("RST: {discovered_port}");
                            }
                        }
                    }
                }
                Ok(None) => { continue; } // This is a timeout
                Err(e) => { eprintln!("Listener error: {}", e); break; }
            }
        }
    });
    Ok(listener_handle)
}

#[cfg(not(feature = "with-libpcap"))]
fn open_capture_thread(
    mut rx: TransportReceiver,
    start: Instant,
    timeout_seconds: u64,
    source_port: u16,
    target_ip: Ipv4Addr,
    lookup_name: bool,
    show_reset: bool,
) -> Result<tokio::task::JoinHandle<()>, NtkError> {
    let listener_handle = tokio::spawn(async move {
        let mut iter = tcp_packet_iter(&mut rx);
        while start.elapsed() < Duration::from_secs(timeout_seconds) {
            let remaining = Duration::from_secs(timeout_seconds).saturating_sub(start.elapsed());
            match iter.next_with_timeout(remaining) {
                Ok(Some((packet, addr))) => {
                    let flags = packet.get_flags();
                    if addr == IpAddr::V4(target_ip) && packet.get_destination() == source_port {
                        if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                            let discovered_port = packet.get_source();
                            if lookup_name {
                                let common_name: &str = port_map().get(&discovered_port).unwrap_or(&"Unknown");
                                println!("{discovered_port}: {common_name}");
                            } else {
                                println!("open: {discovered_port}");
                            }
                        } else if flags & TcpFlags::RST == TcpFlags::RST {
                            let discovered_port = packet.get_source();
                            if show_reset {
                                if lookup_name {
                                    let common_name: &str = port_map().get(&discovered_port).unwrap_or(&"Unknown");
                                    println!("RST: {discovered_port}: {common_name}");
                                } else {
                                    println!("RST: {}", packet.get_source());
                                }
                            }
                        }
                    }
                }
                Ok(None) => { continue; } // This is a timeout
                Err(e) => { eprintln!("Listener error: {}", e); break; }
            }
        }
    });
    Ok(listener_handle)
}

// Construct the BPF filter which will be in-kernel evaluated
#[cfg(feature = "with-libpcap")]
fn bpf_filter(src_ip: Ipv4Addr, dst_port: u16) -> String {
    format!(
        "tcp and src host {} and dst port {}",
        src_ip, dst_port
    )
}

#[cfg(feature = "with-libpcap")]
struct CapturedPacket {
    source_port: u16,
    is_syn_ack: bool,
}

#[cfg(feature = "with-libpcap")]
struct RxHandle {
    handle: std::thread::JoinHandle<()>,
    rx_pcap: tokio::sync::mpsc::UnboundedReceiver<CapturedPacket>,
}

#[cfg(feature = "with-libpcap")]
fn open_capture_thread_ack(
    source_ip: Ipv4Addr,
    source_port: u16,
    target_ip: Ipv4Addr,
    deadline: Instant,
) -> Result<RxHandle, NtkError>
{
    let device = util::find_pcap_device(source_ip)?;

    let mut cap = Capture::from_device(device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .timeout(200)
        .snaplen(256)
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    let filter = bpf_filter(target_ip, source_port);
    cap.filter(&filter, true)
        .or_else(|e| Err(NtkError::LibPacketCaptureFailure(e)))?;

    // this may need to be set if you want the loop to exit naturally
    // the way the program currently works is the handle is dropped
    // and then the OS is assumed to cleanup the thread as the program ends
    // cap.setnonblock()

    let (tx_pcap, rx_pcap) = tokio::sync::mpsc::unbounded_channel::<CapturedPacket>();

    let handle = std::thread::spawn(move || {
        while Instant::now() < deadline {
            match cap.next_packet() {
                Ok(raw) => {
                    if let Some((sport, flags)) = util::parse_tcp_reply(raw.data) {
                        if flags & TcpFlags::RST == TcpFlags::RST {
                            let _ = tx_pcap.send(CapturedPacket { source_port: sport, is_syn_ack: false });
                        }
                    }
                }
                Err(pcap::Error::NoMorePackets) => continue,
                Err(e) => { eprintln!("pcap error: {e}"); break; }
            }
        }

        // println!("DEBUG: Exit thread loop!");
    });

    Ok(RxHandle { handle, rx_pcap })
}

#[cfg(feature = "with-libpcap")]
fn open_capture_thread(
    source_ip: Ipv4Addr,
    source_port: u16,
    target_ip: Ipv4Addr,
    deadline: Instant,
    show_reset: bool,
) -> Result<RxHandle, NtkError>
{
    let device = util::find_pcap_device(source_ip)?;

    let mut cap = Capture::from_device(device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .timeout(200)
        .snaplen(256)
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    let filter = bpf_filter(target_ip, source_port);
    cap.filter(&filter, true)
        .or_else(|e| Err(NtkError::LibPacketCaptureFailure(e)))?;

    // this may need to be set if you want the loop to exit naturally
    // the way the program currently works is the handle is dropped
    // and then the OS is assumed to cleanup the thread as the program ends
    // cap.setnonblock()

    let (tx_pcap, rx_pcap) = tokio::sync::mpsc::unbounded_channel::<CapturedPacket>();

    let handle = std::thread::spawn(move || {
        while Instant::now() < deadline {
            match cap.next_packet() {
                Ok(raw) => {
                    if let Some((sport, flags)) = util::parse_tcp_reply(raw.data) {
                        let is_syn_ack = flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK);
                        let is_rst = flags & TcpFlags::RST == TcpFlags::RST;
                        if is_syn_ack {
                            let _ = tx_pcap.send(CapturedPacket { source_port: sport, is_syn_ack: true });
                        } else if is_rst && show_reset {
                            let _ = tx_pcap.send(CapturedPacket { source_port: sport, is_syn_ack: false });
                        }
                    }
                }
                Err(pcap::Error::NoMorePackets) => continue,
                Err(e) => { eprintln!("pcap error: {e}"); break; }
            }
        }

        // println!("DEBUG: Exit thread loop!");
    });

    Ok(RxHandle { handle, rx_pcap })
}

#[cfg(feature = "with-libpcap")]
async fn rx_tcp_packets_ack(
    timeout_seconds: u64,
    thread_handle: RxHandle,
    lookup_name: bool,
) -> Result<(), NtkError> {
    let RxHandle { handle, mut rx_pcap } = thread_handle;

    let timeout_at = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);

    loop {
        match tokio::time::timeout_at(timeout_at, rx_pcap.recv()).await {
            Ok(Some(CapturedPacket { source_port, is_syn_ack: _ })) => {
                // RST
                if lookup_name {
                    let name = port_map().get(&source_port).unwrap_or(&"Unknown");
                    println!("RST: {source_port}: {name}");
                } else {
                    println!("RST: {source_port}");
                } 
            }
            Ok(None) => break, // channel closed (listener thread exit)
            Err(_elapsed) => break, // timeout
        }
    }

    drop(handle);
    Ok(())
}

#[cfg(feature = "with-libpcap")]
async fn rx_tcp_packets(
    timeout_seconds: u64,
    thread_handle: RxHandle,
    lookup_name: bool,
) -> Result<(), NtkError> {
    let RxHandle { handle, mut rx_pcap } = thread_handle;

    let timeout_at = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);

    loop {
        match tokio::time::timeout_at(timeout_at, rx_pcap.recv()).await {
            Ok(Some(CapturedPacket { source_port, is_syn_ack })) => {
                if is_syn_ack {
                    if lookup_name {
                        let name = port_map().get(&source_port).unwrap_or(&"Unknown");
                        println!("{source_port}: {name}");
                    } else {
                        println!("open: {source_port}");
                    }
                } else {
                    // RST
                    if lookup_name {
                        let name = port_map().get(&source_port).unwrap_or(&"Unknown");
                        println!("RST: {source_port}: {name}");
                    } else {
                        println!("RST: {source_port}");
                    }
                }
            }
            Ok(None) => break, // channel closed (listener thread exit)
            Err(_elapsed) => break, // timeout
        }
    }

    drop(handle);
    Ok(())
}
