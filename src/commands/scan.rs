
use crate::error::NtkError;
use crate::util::{self, debug};
use crate::scan_util::{PortIter, port_map};

use pnet::packet::{MutablePacket};
use pnet::packet::tcp::{
    MutableTcpPacket, TcpFlags
};

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant, Duration};

// // WITH libpcap imports // //
#[cfg(feature = "with-libpcap")]
use pcap::{Capture};

#[cfg(feature = "with-libpcap")]
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
#[cfg(feature = "with-libpcap")]
use pnet::packet::ipv4::{self, MutableIpv4Packet};

#[cfg(feature = "with-libpcap")]
struct PcapSendContext {
    cap: pcap::Capture<pcap::Active>,
    src_mac: pnet::util::MacAddr,
    dst_mac: pnet::util::MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
}
// // // //

// // NOT libpcap imports // //
#[cfg(not(feature = "with-libpcap"))]
use pnet::transport::{
    TransportReceiver,
    tcp_packet_iter,
    transport_channel,
    TransportSender,
    TransportChannelType::Layer4,
    TransportProtocol::Ipv4
};
#[cfg(not(feature = "with-libpcap"))]
use pnet::packet::ip::IpNextHeaderProtocols;
// // // //

// Static sizes that define buffers for ETHERNET, IP, and TCP Packets
#[cfg(feature = "with-libpcap")]
const ETH_HEADER_LEN: usize = 14;
#[cfg(feature = "with-libpcap")]
const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;

/// Determines what window size and shift should be spoofed by our probes
fn get_os_tcp_defaults() -> (u16, u8) {
    // Returns (window_size, wscale_shift)
    match std::env::consts::OS {
        "linux"   => (64240, 7),
        "windows" => (65535, 8),
        "macos"   => (65535, 6),
        _         => (65535, 7), // sane fallback
    }
}

/// A SYN packet is the initial TCP handshake packet
/// You hope to see an SYN and ACK response from an open port
/// This only builds the layer 4 packet buffer- libpcap needs to build layer 3 IP as well
fn build_syn_packet(
    source_ip: &Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    source_port: u16,
) -> Result<Vec<u8>, NtkError> {
    let mut buffer = [0u8; TCP_HEADER_LEN + 20];
    let mut packet = MutableTcpPacket::new(&mut buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;

    let (window_size, wscale) = get_os_tcp_defaults();
    packet.set_source(source_port);
    packet.set_destination(dest_port);
    packet.set_sequence(rand::random());
    // ACK 0 here is important for starting a handshake
    packet.set_acknowledgement(0);
    packet.set_flags(TcpFlags::SYN);
    packet.set_data_offset(10);
    packet.set_window(window_size);

    let buf = packet.packet_mut();
    let opts = &mut buf[20..40];

    // Prefill with NOPs (No Operation) for padding
    opts.fill(1);

    // MSS
    // 0 - MSS (Max Segment Size) - Kind 2
    // 1 - MSS Length (including kind and length)
    // 2 - High byte, 3 - Low byte (together equal 1460)
    opts[0] = 2;  opts[1] = 4;  opts[2] = 0x05; opts[3] = 0xb4;

    // 4 - SACK Permitted (Selective Acknowledgement), 5 - Length
    opts[4] = 4;  opts[5] = 2;

    // Timestamps, 6 - Kind (8), 7 - Length
    opts[6] = 8;  opts[7] = 10;
    // Grab the time right now for the packet
    let tsval = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_millis() & 0xFFFF_FFFF) as u32;
    // Timestamp of sender
    opts[8..12].copy_from_slice(&tsval.to_be_bytes());
    // Echo of tsval rx from other side (tsecr)
    opts[12..16].copy_from_slice(&0u32.to_be_bytes());

    // Window Scale, 16 - Kind 3, 17 - Length (3), 18 - Shift 
    opts[16] = 3; opts[17] = 3; opts[18] = wscale;

    // Without a correct checksum, routers will drop the packet
    packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(), source_ip, &dest_ip,
    ));

    // For debugging, dumping the packet:
    // println!("DEBUG: {:02x?}", packet.packet());

    // Return the packet for sending either via native OS socket or libpcap
    Ok(buffer.to_vec())
}

/// An ACK probe abuses RFC 793 where a host is supposed to respond with 'RST' to this invalid handshake
/// (i.e. a SYN should occur first but doesn't so the host follows protocol and says 'Reset')
/// ACK probes are also commonly not blocked when SYN probes are because the firewall assumes by
/// default that ACK is for an already established connection
/// This only builds the layer 4 packet buffer- libpcap needs to build layer 3 IP as well
fn build_ack_packet(
    source_ip: &Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    source_port: u16,
    fin_probe: bool,
) -> Result<Vec<u8>, NtkError> {
    let mut buffer = [0u8; TCP_HEADER_LEN + 16];
    let mut packet = MutableTcpPacket::new(&mut buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;

    let (window_size, wscale) = get_os_tcp_defaults();
    packet.set_source(source_port);
    packet.set_destination(dest_port);
    packet.set_sequence(rand::random());
    // ACK random here is important to make the receiver believe this is a valid ACK packet (don't use 0)
    packet.set_acknowledgement(rand::random());
    // Offset buffer size is slightly smaller
    packet.set_data_offset(9);
    packet.set_window(window_size);
    packet.set_flags(if fin_probe { TcpFlags::FIN } else { TcpFlags::ACK });

    let buf = packet.packet_mut();
    let opts = &mut buf[20..36];

    // Prefill with NOPs (No Operation) for padding
    opts.fill(1);

    // Timestamps, 0 - Kind (8), 1 - Length (10)
    opts[0] = 8; opts[1] = 10;
    // Get the current time
    let tsval = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_millis() & 0xFFFF_FFFF) as u32;
    // Timestamp of sender
    opts[2..6].copy_from_slice(&tsval.to_be_bytes());
    // echo of tsval rx from other side (tsecr)
    opts[6..10].copy_from_slice(&0u32.to_be_bytes());

    // Window Scale, 10 - Kind (3), 11 - Length (3), 12 - Shift 
    opts[10] = 3; opts[11] = 3; opts[12] = wscale;

    // Without a correct checksum, routers will drop the packet
    packet.set_checksum(pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(), source_ip, &dest_ip,
    ));

    // Return the packet for sending either via native OS socket or libpcap
    Ok(buffer.to_vec())
}

/// Wraps an already-checksummed TCP payload in IPv4 + Ethernet headers
///   and sends it via pcap, bypassing the OS TCP stack entirely.
/// Libpcap operates at the datalink layer so we must supply the full frame —
///   Ethernet header + IP header + TCP payload — for every send.
/// The destination MAC in ctx determines the next hop
/// (target directly if on-link, gateway if off-link).
#[cfg(feature = "with-libpcap")]
fn pcap_send_tcp(ctx: &mut PcapSendContext, tcp_payload: &[u8]) -> Result<(), NtkError> {
    let ip_total_len = IP_HEADER_LEN + tcp_payload.len();
    let frame_len = ETH_HEADER_LEN + ip_total_len;
    let mut frame = vec![0u8; frame_len];

    // libpcap requires the Ethernet Packet frame buffer
    {
        let mut eth = MutableEthernetPacket::new(&mut frame)
            .ok_or(NtkError::PacketBufferTooSmall)?;
        eth.set_destination(ctx.dst_mac);
        eth.set_source(ctx.src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    // And the IP Packet buffer
    {
        let mut ip = MutableIpv4Packet::new(&mut frame[ETH_HEADER_LEN..])
            .ok_or(NtkError::PacketBufferTooSmall)?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(ip_total_len as u16);
        ip.set_identification(rand::random());
        ip.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
        ip.set_source(ctx.source_ip);
        ip.set_destination(ctx.target_ip);
        ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
    }

    frame[ETH_HEADER_LEN + IP_HEADER_LEN..].copy_from_slice(tcp_payload);

    ctx.cap.sendpacket(&*frame)
        .map_err(NtkError::LibPacketCaptureFailure)
}

/// Builds and sends a single SYN probe packet.
/// Relies on pnet (or the OS) to construct the Ethernet and IP frames
#[cfg(not(feature = "with-libpcap"))]
fn send_syn_packet(
    source_ip: &Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    tx: &mut TransportSender,
    source_port: u16,
) -> Result<(), NtkError> {
    let mut bytes = build_syn_packet(source_ip, dest_ip, dest_port, source_port)?;
    tx.send_to(
        MutableTcpPacket::new(&mut bytes).ok_or(NtkError::PacketBufferTooSmall)?,
        dest_ip.into(),
    ).map_err(NtkError::PacketSendFailure)?;
    Ok(())
}

/// Builds and sends a single ACK (or FIN) probe packet.
/// Relies on pnet (or the OS) to construct the Ethernet and IP frames
#[cfg(not(feature = "with-libpcap"))]
fn send_ack_packet(
    source_ip: &Ipv4Addr,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    tx: &mut TransportSender,
    source_port: u16,
    fin_probe: bool,
) -> Result<(), NtkError> {
    let mut bytes = build_ack_packet(source_ip, dest_ip, dest_port, source_port, fin_probe)?;
    tx.send_to(
        MutableTcpPacket::new(&mut bytes).ok_or(NtkError::PacketBufferTooSmall)?,
        dest_ip.into(),
    ).map_err(NtkError::PacketSendFailure)?;
    Ok(())
}


/// Collects the netdev interface for the provided inferface_name
/// Falls back to searching on a source_ip if the interface_name is not provided
fn get_netdev_interface(
    verbose: bool,
    interface_name: Option<String>,
    source_ip: Ipv4Addr,
) -> Result<netdev::Interface, NtkError> {
    let interface_map = util::NetdevInterfaceNameMap::build();
    let nd_iface = match interface_name {
        Some(iface_name) => {
            debug!(verbose, "Using interface name for interface selection: {iface_name}");
            interface_map.resolve_netdev(&iface_name)
                .ok_or(NtkError::IfNameNotFound(String::from(iface_name)))?
        }
        None => {
            debug!(verbose, "Using discovered source IP for interface selection: {source_ip}");
            // Get the netdev interface for gateway MAC already resolved by the OS
            netdev::get_interfaces()
                .into_iter()
                .find(|i| i.ipv4.iter().any(|net| net.addr() == source_ip))
                .ok_or(NtkError::IpIfAssociationError(source_ip.to_string()))?
        }
    };
    debug!(verbose, "Using interface: {}", nd_iface.name);
    Ok(nd_iface)
}

/// Validate that our bind trick to figure out the source IP actually matches what netdev discovered for IPv4 Addresses
fn validate_source_ip(
    verbose: bool,
    netdev_interface: &netdev::Interface,
    source_ip: Ipv4Addr,
) -> Result<Ipv4Addr, NtkError> {
    if !netdev_interface.ipv4_addrs().contains(&source_ip) {
        debug!(verbose, "Computed source IP: {source_ip} is not contained within the known interface IPv4 addresses! Falling back to first available on interface...");
        if netdev_interface.ipv4_addrs().len() > 0 {
            Ok(netdev_interface.ipv4_addrs()[0])
        } else {
            Err(NtkError::IpIfAssociationError(source_ip.to_string()))
        }
    } else {
        debug!(verbose, "Validated that the bound source IP matches an available IP on the specified interface.");
        Ok(source_ip)
    }
}

/// Handles the transport setup (i.e. the channels)
/// This variant is for non-libpcap (i.e. native socket mode)
#[cfg(not(feature = "with-libpcap"))]
async fn handle_transport_setup(
    ip_str: &str, 
    user_source_port: Option<u16>,
    verbose: bool,
    interface_name: Option<String>,
) -> Result<
        (Ipv4Addr, u16, TransportSender, TransportReceiver, Ipv4Addr, Instant),
        NtkError>
    {
    let target_ip = util::str_or_hostname_to_ipv4(ip_str).await;
    let source_port: u16 = match user_source_port {
        Some(p) => { p }
        None => { rand::random_range(32768..61000) }
    };
    debug!(verbose, "Using source port: {source_port}");

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (tx, rx) = match transport_channel(65536, protocol) {
        Ok(channels) => channels,
        Err(e) => return Err(NtkError::DatalinkOpenFailure(e)),
    };
    debug!(verbose, "Opened transport channel on native socket!");

    let mut source_ip = match util::compute_source_ip(&ip_str) {
        IpAddr::V4(ip) => { ip }
        IpAddr::V6(_) => { return Err(NtkError::Ipv6FoundError) }
    };
    source_ip = validate_source_ip(
        verbose,
        &get_netdev_interface(verbose, interface_name, source_ip)?,
        source_ip
    )?;
    debug!(verbose, "Using source IP: {source_ip}");

    let start = Instant::now();
    Ok((target_ip, source_port, tx, rx, source_ip, start))
}

/// Handles the common transport setup
/// This variant is for libpcap enabled builds
#[cfg(feature = "with-libpcap")]
async fn handle_transport_setup_pcap(
    ip_str: &str,
    user_source_port: Option<u16>,
    verbose: bool,
    interface_name: Option<String>,
) -> Result<PcapSendContext, NtkError> {
    let target_ip = util::str_or_hostname_to_ipv4(ip_str).await;
    let source_port = user_source_port
        .unwrap_or_else(|| rand::random_range(32768..61000));
    debug!(verbose, "Using source port: {source_port}");

    let mut source_ip = match util::compute_source_ip(ip_str) {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(NtkError::Ipv6FoundError),
    };

    let nd_iface = get_netdev_interface(verbose, interface_name, source_ip)?;
    source_ip = validate_source_ip(verbose, &nd_iface, source_ip)?;
    debug!(verbose, "Using source IP: {source_ip}");

    let src_mac = nd_iface.mac_addr
        .ok_or(NtkError::SourceMacAddressFailure(nd_iface.name.clone()))
        .map(|m| { let o = m.octets(); pnet::util::MacAddr(o[0],o[1],o[2],o[3],o[4],o[5]) })?;
    debug!(verbose, "Source MAC for ethernet frame is: {src_mac}");

    let on_link = nd_iface.ipv4.iter()
        .any(|net| net.contains(&target_ip));

    let dst_mac = if on_link {
        // Same subnet: must ARP for the target directly (First hop Mac required in packet)
        debug!(verbose, "Destination MAC is 'on link' for this subnet.");
        let pnet_iface = pnet::datalink::interfaces()
            .into_iter()
            .find(|i| i.ips.iter().any(|net| net.ip() == IpAddr::V4(source_ip)))
            .ok_or(NtkError::IpIfAssociationError(source_ip.to_string()))?;
        crate::commands::discover::resolve_mac_for_ip(
            &pnet_iface,
            source_ip,
            target_ip,
            Duration::from_secs(3),
        )?
    } else {
        debug!(verbose, "Destination MAC is outside this subnet");

        let zero = netdev::MacAddr::new(0, 0, 0, 0, 0, 0);

        // Fast path: netdev resolved gateway MAC
        let netdev_mac = nd_iface.gateway
            .as_ref()
            .filter(|gw| gw.mac_addr != zero)
            .map(|gw| {
                let o = gw.mac_addr.octets();
                pnet::util::MacAddr(o[0], o[1], o[2], o[3], o[4], o[5])
            });

        if let Some(mac) = netdev_mac {
            debug!(verbose, "Using gateway MAC resolved by netdev: {mac}");
            mac
        } else {
            // Resolve gateway IP: netdev gateway field, then netlink on Linux
            let gw_ip = nd_iface.gateway
                .as_ref()
                .and_then(|gw| gw.ipv4.first().copied())
                .or_else(|| {
                    #[cfg(all(feature = "with-libpcap", target_os = "linux"))]
                    { get_gateway_ip_via_netlink(target_ip, verbose) }
                    #[cfg(not(target_os = "linux"))]
                    { None }
                })
                .ok_or_else(|| NtkError::GatewayResolutionFailure(
                    format!("no gateway found for interface {}", nd_iface.name)
                ))?;
            debug!(verbose, "Resolved gateway IP: {gw_ip}");

            // Try ARP cache before sending ARP packets
            #[cfg(all(feature = "with-libpcap", target_os = "linux"))]
            if let Some(mac) = get_gateway_mac_from_arp_cache(gw_ip, &nd_iface.name) {
                debug!(verbose, "Using gateway MAC from ARP cache: {mac}");
                return Ok(PcapSendContext {
                    cap: {
                        Capture::from_device(util::find_pcap_device(source_ip)?)
                            .map_err(NtkError::LibPacketCaptureFailure)?
                            .timeout(0)
                            .snaplen(0)
                            .promisc(false)
                            .open()
                            .map_err(NtkError::LibPacketCaptureFailure)?
                    },
                    src_mac,
                    dst_mac: mac,
                    source_ip,
                    target_ip,
                    source_port,
                });
            }

            // Last resort: send ARP request
            let pnet_iface = pnet::datalink::interfaces()
                .into_iter()
                .find(|i| i.ips.iter().any(|net| net.ip() == IpAddr::V4(source_ip)))
                .ok_or(NtkError::IpIfAssociationError(source_ip.to_string()))?;
            debug!(verbose, "ARPing for gateway MAC at {gw_ip}");
            crate::commands::discover::resolve_mac_for_ip(
                &pnet_iface,
                source_ip,
                gw_ip,
                Duration::from_secs(3),
            )?
        }
    };
    debug!(verbose, "Destination MAC for ethernet frame is: {dst_mac}");

    debug!(verbose, "Opening pcap capture channel for transmit...");
    let send_cap = Capture::from_device(util::find_pcap_device(source_ip)?)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .timeout(0)
        .snaplen(0)
        .promisc(false)
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    let ctx = PcapSendContext {
        cap: send_cap,
        src_mac,
        dst_mac,
        source_ip,
        target_ip,
        source_port,
    };
    debug!(verbose, "Transmit channel OK!");

    Ok(ctx)
}

/// Creates channels applicable to the with-libpcap feature or without (i.e. native socket)
///   and sends TCP SYN probe packets to the target IP.
/// By default will scan an internal array of the 1000 most commonly used ports for 'open' status.
pub async fn run_tcp_syn_probe(
    ip_str: &str, lookup_name: bool,
    delay: u64, start_range: Option<u16>,
    end_range: Option<u16>,
    timeout_seconds: u8,
    show_reset: bool,
    user_source_port: Option<u16>,
    verbose: bool,
    interface_name: Option<String>,
) -> Result<(), NtkError> {
    #[cfg(feature = "with-libpcap")]
    let mut ctx
        = handle_transport_setup_pcap(ip_str, user_source_port, verbose, interface_name).await?;
    
    #[cfg(not(feature = "with-libpcap"))]
    let (target_ip, source_port, mut tx, rx, source_ip, start)
        = handle_transport_setup(ip_str, user_source_port, verbose, interface_name).await?;

    let timeout_seconds = timeout_seconds as u64;
    // Calculate the total time to wait
    // We need to figure in the delay in-between each send
    // Otherwise we won't wait long enough for all packets
    // to return to us
    let port_count = PortIter::new(start_range, end_range).count() as u64;
    let send_duration = Duration::from_millis(port_count * delay);
    let capture_duration = send_duration + Duration::from_secs(timeout_seconds);
    
    #[cfg(feature = "with-libpcap")]
    let handle = open_capture_thread(ctx.source_ip, ctx.source_port, ctx.target_ip, show_reset, capture_duration, verbose)?;

    #[cfg(not(feature = "with-libpcap"))]
    let _handle = open_capture_thread(rx, start, capture_duration, source_port, target_ip, lookup_name, show_reset, verbose)?;

    #[cfg(feature = "with-libpcap")]
    let drain = tokio::spawn(rx_tcp_packets(capture_duration, handle, lookup_name, verbose));

    for port in PortIter::new(start_range, end_range) {
        debug!(verbose, "Sending: {port}");
        #[cfg(not(feature = "with-libpcap"))]
        {
            match send_syn_packet(&source_ip, target_ip, port, &mut tx, source_port) {
                Ok(()) => {}
                Err(e) => { return Err(e); }
            };
        }
        #[cfg(feature = "with-libpcap")]
        {
            let tcp_bytes = build_syn_packet(&ctx.source_ip, ctx.target_ip, port, ctx.source_port)?;
            match pcap_send_tcp(&mut ctx, &tcp_bytes) {
                Ok(()) => {}
                Err(e) => { return Err(e); }
            };
        }
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    debug!(verbose, "Send complete. Awaiting responses...");

    #[cfg(feature = "with-libpcap")]
    drain.await.map_err(|_| NtkError::TaskJoinError)??;

    #[cfg(not(feature = "with-libpcap"))]
    tokio::time::sleep(Duration::from_secs(timeout_seconds as u64)).await;
    
    Ok(())
}

/// Creates channels applicable to the with-libpcap feature or without (i.e. native socket)
///   and sends TCP ACK (or FIN) probe packets to the target IP.
/// For these ACK scans you expect 'RST' (reset) responses instead of 'open'.
/// By default will scan an internal array of the 1000 most commonly used ports for 'open' status.
pub async fn run_tcp_ack_probe(ip_str: &str,
    lookup_name: bool,
    delay: u64,
    start_range: Option<u16>,
    end_range: Option<u16>,
    timeout_seconds: u8,
    user_source_port: Option<u16>,
    fin_probe: bool,
    verbose: bool,
    interface_name: Option<String>,
) -> Result<(), NtkError> {
    #[cfg(feature = "with-libpcap")]
    let mut ctx 
        = handle_transport_setup_pcap(ip_str, user_source_port, verbose, interface_name).await?;
    
    #[cfg(not(feature = "with-libpcap"))]
    let (target_ip, source_port, mut tx, rx, source_ip, start)
        = handle_transport_setup(ip_str, user_source_port, verbose, interface_name).await?;

    let timeout_seconds = timeout_seconds as u64;
    // Calculate the total time to wait
    // We need to figure in the delay in-between each send
    // Otherwise we won't wait long enough for all packets
    // to return to us
    let port_count = PortIter::new(start_range, end_range).count() as u64;
    let send_duration = Duration::from_millis(port_count * delay);
    let capture_duration = send_duration + Duration::from_secs(timeout_seconds);
    
    #[cfg(feature = "with-libpcap")]
    let handle = open_capture_thread_ack(ctx.source_ip, ctx.source_port, ctx.target_ip, capture_duration, verbose)?;

    #[cfg(not(feature = "with-libpcap"))]
    let _handle = open_capture_thread_ack(rx, start, capture_duration, source_port, target_ip, lookup_name, verbose)?;

    #[cfg(feature = "with-libpcap")]
    let drain = tokio::spawn(rx_tcp_packets_ack(capture_duration, handle, lookup_name));

    for port in PortIter::new(start_range, end_range) {
        // println!("Sending: {}", port);
        #[cfg(not(feature = "with-libpcap"))]
        {
            match send_ack_packet(&source_ip, target_ip, port, &mut tx, source_port, fin_probe) {
                Ok(()) => {}
                Err(e) => { return Err(e); }
            };
        }
        #[cfg(feature = "with-libpcap")]
        {
            let tcp_bytes = build_ack_packet(&ctx.source_ip, ctx.target_ip, port, ctx.source_port, fin_probe)?;
            match pcap_send_tcp(&mut ctx, &tcp_bytes) {
                Ok(()) => {}
                Err(e) => { return Err(e); }
            };
        }
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    #[cfg(feature = "with-libpcap")]
    drain.await.map_err(|_| NtkError::TaskJoinError)??;

    #[cfg(not(feature = "with-libpcap"))]
    tokio::time::sleep(Duration::from_secs(timeout_seconds as u64)).await;   

    Ok(())
}

/// Creates a thread that listens for SYN+ACK responses
/// These indicate a port is 'open'
#[cfg(not(feature = "with-libpcap"))]
fn open_capture_thread(
    mut rx: TransportReceiver,
    start: Instant,
    capture_duration: Duration,
    source_port: u16,
    target_ip: Ipv4Addr,
    lookup_name: bool,
    show_reset: bool,
    verbose: bool,
) -> Result<tokio::task::JoinHandle<()>, NtkError> {
    debug!(verbose, "Spawning thread to monitor capture...");
    let listener_handle = tokio::spawn(async move {
        let mut iter = tcp_packet_iter(&mut rx);
        while start.elapsed() < capture_duration {
            let remaining = capture_duration.saturating_sub(start.elapsed());
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
    debug!(verbose, "Capture thread spawned!");
    Ok(listener_handle)
}

/// Creates a thread that listens for RST responses
#[cfg(not(feature = "with-libpcap"))]
fn open_capture_thread_ack(
    mut rx: TransportReceiver,
    start: Instant,
    capture_duration: Duration,
    source_port: u16,
    target_ip: Ipv4Addr,
    lookup_name: bool,
    verbose: bool,
) -> Result<tokio::task::JoinHandle<()>, NtkError> {
    debug!(verbose, "Spawning thread to monitor capture...");
     let listener_handle = tokio::spawn(async move {
        let mut iter = tcp_packet_iter(&mut rx);
        while start.elapsed() < capture_duration {
            let remaining = capture_duration.saturating_sub(start.elapsed());
            match iter.next_with_timeout(remaining) {
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
    debug!(verbose, "Capture thread spawned!");
    Ok(listener_handle)
}


/// Construct the BPF filter which will be in-kernel/driver evaluated.
/// These filters are passed into libpcap similar to how you would
///   filter in wireshark or tcpdump.
///
/// `target_ip`   — only capture packets coming from the host we are scanning
/// `source_port` — the ephemeral port we sent probes *from*; responses arrive
///                 *to* this port, so it maps to `dst port` in the filter
///
/// The flag constraint restricts capture to SYN+ACK and RST only, which covers
/// all three scan types (SYN, ACK, FIN). This also prevents Npcap on Windows
/// from delivering duplicate entries caused by the Windows TCP/IP stack firing
/// its own RST in response to an unsolicited SYN+ACK.
#[cfg(feature = "with-libpcap")]
fn bpf_filter(target_ip: Ipv4Addr, source_port: u16) -> String {
    format!(
        "tcp and src host {target_ip} and dst port {source_port} \
         and (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack) \
         or tcp[tcpflags] & tcp-rst != 0)"
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

/// The libpcap implementation of opening a thread to capture SYN+ACK responses
#[cfg(feature = "with-libpcap")]
fn open_capture_thread(
    source_ip: Ipv4Addr,
    source_port: u16,
    target_ip: Ipv4Addr,
    show_reset: bool,
    capture_duration: Duration,
    verbose: bool,
) -> Result<RxHandle, NtkError>
{
    debug!(verbose, "Opening pcap capture rx channel...");
    let device = util::find_pcap_device(source_ip)?;

    let mut cap = Capture::from_device(device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .timeout(200)
        .snaplen(512)
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    debug!(verbose, "Appling bpf filter to opened pcap rx channel...");
    let filter = bpf_filter(target_ip, source_port);
    cap.filter(&filter, true)
        .or_else(|e| Err(NtkError::LibPacketCaptureFailure(e)))?;

    // this may need to be set if you want the loop to exit naturally
    // the way the program currently works is the handle is dropped
    // and then the OS is assumed to cleanup the thread as the program ends
    // cap.setnonblock()

    // A channel just to signal the rx thread is ready
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    // The actual communications channels
    let (tx_pcap, rx_pcap) = tokio::sync::mpsc::unbounded_channel::<CapturedPacket>();

    debug!(verbose, "Spawning thread to monitor capture...");
    let handle = std::thread::spawn(move || {
        let mut seen = std::collections::HashSet::new();
        // On Windows/Npcap the BPF filter activation in the NDIS driver is
        // asynchronous. Block on one next_packet() call to ensure the filter
        // is live before signaling ready. On Unix this is unnecessary and
        // next_packet() may block indefinitely, so we skip it.
        #[cfg(target_os = "windows")]
        let _ = cap.next_packet();

        ready_tx.send(()).ok();
        let deadline = Instant::now() + capture_duration;

        while Instant::now() < deadline {
            match cap.next_packet() {
                Ok(raw) => {
                    if let Some((sport, flags)) = util::parse_tcp_reply(raw.data) {
                        let is_syn_ack = flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK);
                        let is_rst = flags & TcpFlags::RST == TcpFlags::RST;
                        if is_syn_ack && !seen.contains(&sport) {
                            seen.insert(sport);
                            let _ = tx_pcap.send(CapturedPacket { source_port: sport, is_syn_ack: true });
                        } else if is_rst && show_reset && !seen.contains(&sport) {
                            seen.insert(sport);
                            let _ = tx_pcap.send(CapturedPacket { source_port: sport, is_syn_ack: false });
                        }
                    }
                }
                Err(pcap::Error::NoMorePackets) => continue,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => { eprintln!("pcap error: {e}"); break; }
            }
        }
        // println!("DEBUG: Exit thread loop!");
    });

    // wait for the thread to be ready to rx packets
    ready_rx.recv().ok();
    debug!(verbose, "Rx channel OK!");

    Ok(RxHandle { handle, rx_pcap })
}

/// The libpcap implementation of opening a thread to capture RST responses
#[cfg(feature = "with-libpcap")]
fn open_capture_thread_ack(
    source_ip: Ipv4Addr,
    source_port: u16,
    target_ip: Ipv4Addr,
    capture_duration: Duration,
    verbose: bool,
) -> Result<RxHandle, NtkError>
{
    debug!(verbose, "Opening pcap capture rx channel...");
    let device = util::find_pcap_device(source_ip)?;

    let mut cap = Capture::from_device(device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .timeout(200)
        .snaplen(512)
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    debug!(verbose, "Appling bpf filter to opened pcap rx channel...");
    let filter = bpf_filter(target_ip, source_port);
    cap.filter(&filter, true)
        .or_else(|e| Err(NtkError::LibPacketCaptureFailure(e)))?;

    // this may need to be set if you want the loop to exit naturally
    // the way the program currently works is the handle is dropped
    // and then the OS is assumed to cleanup the thread as the program ends
    // cap.setnonblock()

    // A channel just to signal the rx thread is ready
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let (tx_pcap, rx_pcap) = tokio::sync::mpsc::unbounded_channel::<CapturedPacket>();

    debug!(verbose, "Spawning thread to monitor capture...");
    let handle = std::thread::spawn(move || {
        let mut seen = std::collections::HashSet::new();
        // On Windows/Npcap the BPF filter activation in the NDIS driver is
        // asynchronous. Block on one next_packet() call to ensure the filter
        // is live before signaling ready. On Unix this is unnecessary and
        // next_packet() may block indefinitely, so we skip it.
        #[cfg(target_os = "windows")]
        let _ = cap.next_packet();

        ready_tx.send(()).ok();
        let deadline = Instant::now() + capture_duration;
        while Instant::now() < deadline {
            match cap.next_packet() {
                Ok(raw) => {
                    if let Some((sport, flags)) = util::parse_tcp_reply(raw.data) {
                        if flags & TcpFlags::RST == TcpFlags::RST && !seen.contains(&sport) {
                            seen.insert(sport);
                            let _ = tx_pcap.send(CapturedPacket { source_port: sport, is_syn_ack: false });
                        }
                    }
                }
                Err(pcap::Error::NoMorePackets) => continue,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => { eprintln!("pcap error: {e}"); break; }
            }
        }

        // println!("DEBUG: Exit thread loop!");
    });

    // wait for the thread to be ready to rx packets
    ready_rx.recv().ok();
    debug!(verbose, "Rx channel OK!");

    Ok(RxHandle { handle, rx_pcap })
}

/// Drains the TCP Packet responses from the capture thread after all sends have completed.
/// ACK/FIN probe specific
#[cfg(feature = "with-libpcap")]
async fn rx_tcp_packets_ack(
    capture_duration: Duration,
    thread_handle: RxHandle,
    lookup_name: bool,
) -> Result<(), NtkError> {
    let RxHandle { handle, mut rx_pcap } = thread_handle;

    let timeout_at = tokio::time::Instant::now() + capture_duration;

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

/// Drains the TCP Packet responses from the capture thread after all sends have completed.
/// SYN probe specific
#[cfg(feature = "with-libpcap")]
async fn rx_tcp_packets(
    capture_duration: Duration,
    thread_handle: RxHandle,
    lookup_name: bool,
    verbose: bool,
) -> Result<(), NtkError> {
    let RxHandle { handle, mut rx_pcap } = thread_handle;

    let timeout_at = tokio::time::Instant::now() + capture_duration;
    debug!(verbose, "Draining TCP responses in thread...");
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

    debug!(verbose, "Dropping Rx thread handle...");
    drop(handle);
    debug!(verbose, "Dropped handle.");
    Ok(())
}

#[cfg(all(feature = "with-libpcap", target_os = "linux"))]
fn get_gateway_ip_via_netlink(target_ip: Ipv4Addr, verbose: bool) -> Option<Ipv4Addr> {
    debug!(verbose, "Failed to resolve gateway MAC using netdev create. Falling back to netlink...");

    use netlink_packet_core::{NetlinkMessage, NetlinkHeader, NLM_F_REQUEST};
    use netlink_packet_route::{
        AddressFamily,
        RouteNetlinkMessage,
        route::{RouteMessage, RouteAttribute, RouteHeader, RouteProtocol, RouteScope, RouteType, RouteAddress},
    };
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

    debug!(verbose, "Grabbing socket...");
    let mut socket = Socket::new(NETLINK_ROUTE).ok()?;
    debug!(verbose, "Grabbing address...");
    let addr = SocketAddr::new(0, 0);
    debug!(verbose, "Address is: {:?}", addr);
    socket.bind_auto().ok()?;
    socket.connect(&addr).ok()?;

    let mut route_msg = RouteMessage::default();
    route_msg.header = RouteHeader {
        address_family: AddressFamily::Inet,
        destination_prefix_length: 32,
        protocol: RouteProtocol::Unspec,
        scope: RouteScope::Universe,
        kind: RouteType::Unicast,
        ..Default::default()
    };
    route_msg.attributes.push(
        RouteAttribute::Destination(RouteAddress::Inet(target_ip))
    );

    let mut nl_msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        RouteNetlinkMessage::GetRoute(route_msg).into(),
    );
    nl_msg.header.flags = NLM_F_REQUEST;
    nl_msg.finalize();

    debug!(verbose, "Finalized netlink message, building buffer...");

    let mut buf = vec![0u8; nl_msg.buffer_len()];
    nl_msg.serialize(&mut buf);

    debug!(verbose, "Sending netlink message...");

    socket.send(&buf, 0).ok()?;

    debug!(verbose, "Awaiting rx...");

    let mut recv_buf = vec![0u8; 4096];
    let n = socket.recv(&mut recv_buf, 0).ok()?;

    let response = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[..n]).ok()?;
    
    debug!(verbose, "Unwrapping payload response: {:?}...", response);

    // payload is NetlinkPayload<RouteNetlinkMessage>, unwrap the inner message
    use netlink_packet_core::NetlinkPayload;
    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(msg)) = response.payload {
        for attr in &msg.attributes {
            if let RouteAttribute::Gateway(RouteAddress::Inet(gw)) = attr {
                return Some(*gw);
            }
        }
    }

    None
}

#[cfg(all(feature = "with-libpcap", target_os = "linux"))]
fn get_gateway_mac_from_arp_cache(
    gateway_ip: Ipv4Addr,
    iface_name: &str,
) -> Option<pnet::util::MacAddr> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 { continue; }
        let ip: Ipv4Addr = cols[0].parse().ok()?;
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
        let dev = cols[5];
        // 0x2 = ATF_COM (complete, valid entry)
        if ip == gateway_ip && dev == iface_name && flags & 0x2 != 0 {
            let mac = cols[3];
            let parts: Vec<u8> = mac.split(':')
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if parts.len() == 6 {
                return Some(pnet::util::MacAddr(
                    parts[0], parts[1], parts[2],
                    parts[3], parts[4], parts[5],
                ));
            }
        }
    }
    None
}