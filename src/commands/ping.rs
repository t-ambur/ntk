
use crate::error::NtkError;
use crate::util;

use pnet::packet::icmp::{
    echo_request::MutableEchoRequestPacket,
    IcmpTypes,
    IcmpPacket
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    transport_channel,
    TransportSender,
    TransportChannelType::Layer4,
    TransportProtocol::Ipv4
};

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration};

// // WITH libpcap imports // //
#[cfg(feature = "with-libpcap")]
use crate::util::IcmpResponse;
#[cfg(feature = "with-libpcap")]
use pcap::Capture;
#[cfg(feature = "with-libpcap")]
use std::time::{Instant};
// // // //

// // NOT libpcap imports // //
#[cfg(not(feature = "with-libpcap"))]
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
#[cfg(not(feature = "with-libpcap"))]
use pnet::transport::{icmp_packet_iter, IcmpTransportChannelIterator, TransportReceiver};
// // // //

// // WITH libpcap // //
#[cfg(feature = "with-libpcap")]
struct CapturedPacket {
    seq: u16,
    src: IpAddr,
    is_final: bool,
    is_timeout: bool,
    rx_time: Duration,
}

#[cfg(feature = "with-libpcap")]
struct RxHandle {
    handle: std::thread::JoinHandle<()>,
    rx_pcap: tokio::sync::mpsc::UnboundedReceiver<CapturedPacket>,
}

#[cfg(feature = "with-libpcap")]
fn resolve_source_ipv4(target_ip: &Ipv4Addr) -> Result<Ipv4Addr, NtkError> {
    match util::compute_source_ip(&target_ip.to_string()) {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(NtkError::Ipv6FoundError),
    }
}

/// The type F is a generic function here
/// The input must be a slice of bytes and the function must return an Option<CapturedPacket>
/// It must implement 'Send' and 'static because it will be passed into a thread
/// We define this criteria to create a function that accepts a filter and a parser (common between ping and traceroute) for pcap
/// It uses 'monomorphism' at compile time to stamp out a unique copy per closure
#[cfg(feature = "with-libpcap")]
fn open_capture_thread<F>(
    source_ip: Ipv4Addr,
    filter: &str,
    deadline: Instant,
    parser: F,
) -> Result<RxHandle, NtkError>
where
    F: Fn(&[u8]) -> Option<CapturedPacket> + Send + 'static,
{
    let device = util::find_pcap_device(source_ip)?;

    let mut cap = Capture::from_device(device)
        .map_err(NtkError::LibPacketCaptureFailure)?
        .timeout(200)
        .snaplen(256)
        .open()
        .map_err(NtkError::LibPacketCaptureFailure)?;

    cap.filter(filter, true)
        .map_err(NtkError::LibPacketCaptureFailure)?;

    // this may need to be set if you want the loop to exit naturally
    // the way the program currently works is the handle is dropped
    // and then the OS is assumed to cleanup the thread as the program ends
    // cap.setnonblock()

    let (tx_pcap, rx_pcap) = tokio::sync::mpsc::unbounded_channel::<CapturedPacket>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();

    let handle = std::thread::spawn(move || {
        ready_tx.send(()).ok();
        while Instant::now() < deadline {
            match cap.next_packet() {
                Ok(raw) => {
                    let ts = raw.header.ts;
                    let rx_time = Duration::new(ts.tv_sec as u64, ts.tv_usec as u32 * 1000);
                    if let Some(pkt) = parser(raw.data) {
                        let _ = tx_pcap.send(CapturedPacket { rx_time, ..pkt });
                    }
                }
                Err(pcap::Error::NoMorePackets) => continue,
                Err(e) => { eprintln!("pcap error: {e}"); break; }
            }
        }

        // println!("DEBUG: Exit thread loop!");
    });

    ready_rx.recv().ok();
    Ok(RxHandle { handle, rx_pcap })
}

/// Creates a thread to listen for echo replies.
/// Also handles creation of the bpf filter on icmp-echoreply
#[cfg(feature = "with-libpcap")]
async fn setup_rx_ping(
    target_ip: Ipv4Addr,
    timeout_seconds: u64,
) -> Result<Option<RxHandle>, NtkError> {
    let source_ip = resolve_source_ipv4(&target_ip)?;
    let filter = format!(
        "icmp and (icmp[icmptype] = icmp-echoreply or icmp[icmptype] = 11)"
    );
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);

    // The closure here has a map that converts the result from
    // parse_icmp_reply into a CapturedPacket if Some() else None
    let handle = open_capture_thread(source_ip, &filter, deadline, |data| {
        match util::parse_icmp_packet(data)? {
            IcmpResponse::EchoReply { seq, src } => {
                Some(CapturedPacket { seq, src, is_final: true, is_timeout: false, rx_time: Duration::default() })
            }
            IcmpResponse::TimeExceeded { seq, src } => {
                Some(CapturedPacket { seq, src, is_final: true, is_timeout: true, rx_time: Duration::default() })
            }
        }
    })?;

    Ok(Some(handle))
}

/// Drains the capture thread created after all pings have been sent
#[cfg(feature = "with-libpcap")]
async fn rx_icmp_packets(
    timeout_seconds: u64,
    start_times: Vec<Duration>,
    thread_handle: Option<RxHandle>,
) -> Result<(), NtkError> {
    let RxHandle { handle, mut rx_pcap } = thread_handle
        .ok_or(NtkError::UnexpectedHandle)?;

    let timeout_at = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
    let mut received = 0;
    let count = start_times.len();

    loop {
        match tokio::time::timeout_at(timeout_at, rx_pcap.recv()).await {
            Ok(Some(CapturedPacket { seq, src, is_final: _, is_timeout, rx_time })) => {
                let idx = seq as usize - 1;
                if let Some(&sent_at) = start_times.get(idx) {
                    if is_timeout {
                        println!("{:<seq_w$} {:<ip_w$} *", seq, src, seq_w = 3, ip_w = 16);
                    } else {
                        let elapsed = rx_time - sent_at;
                        println!("{:<seq_w$} {:<ip_w$} {:.2?}", seq, src, elapsed,
                                seq_w = 3, ip_w = 16);
                    }
                } else {
                    eprintln!("seq {} out of range", seq);
                }
                received += 1;
                if received >= count { break; }
            }
            Ok(None) => break, // channel closed, thread exited
            Err(_elapsed) => {
                // asterisk for any seq we never heard back from
                for i in 0..count {
                    let seq = i + 1;
                    println!("{} *", seq);
                }
                break;
            }
        }
    }

    drop(handle);
    Ok(())
}

/// Creates a thread to listen for timeout replies.
/// Also handles creation of the bpf filter on icmp-time-exceeded
#[cfg(feature = "with-libpcap")]
async fn setup_rx_traceroute(
    target_ip: Ipv4Addr,
    timeout_seconds: u64,
) -> Result<Option<RxHandle>, NtkError> {
    // For traceroute we don't know the source IPs of intermediate hops ahead
    // of time, so we pick our outbound interface from a well-known address and
    // capture all ICMP echo-reply / time-exceeded traffic.
    let source_ip = resolve_source_ipv4(&target_ip)?;
    let filter =
        "icmp and (icmp[icmptype] = icmp-echoreply or icmp[icmptype] = 11)" // 11 is icmp-time-exceeded
            .to_string();
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);

    let handle = open_capture_thread(source_ip, &filter, deadline, |data| {
        match util::parse_icmp_packet(data)? {
            IcmpResponse::EchoReply { seq, src } =>
                Some(CapturedPacket { seq, src, is_final: true, is_timeout: false, rx_time: Duration::default() }),
            IcmpResponse::TimeExceeded { seq, src } =>
                Some(CapturedPacket { seq, src, is_final: false, is_timeout: true, rx_time: Duration::default() }),
        }
    })?;

    Ok(Some(handle))
}

/// Drains the capture thread created after all (traceroute) 'pings' have been sent
#[cfg(feature = "with-libpcap")]
async fn rx_tr_packets(
    thread_handle: Option<RxHandle>,
    hops: Vec<(u8, Duration)>,
    timeout_seconds: u64,
    target_ip: Ipv4Addr,
) -> Result<(), NtkError> {
    let RxHandle { handle, mut rx_pcap } = thread_handle
        .ok_or(NtkError::UnexpectedHandle)?;

    let timeout_at = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
    let count = hops.len();
    let mut received: usize = 0;
    let mut next_ttl: u8 = 1;
    let mut stash: std::collections::HashMap<u8, (IpAddr, Duration, bool, Duration)> = std::collections::HashMap::new();

    loop {
        match tokio::time::timeout_at(timeout_at, rx_pcap.recv()).await {
            Ok(Some(CapturedPacket { seq, src, is_final, is_timeout: _, rx_time })) => {
                let idx = seq as usize - 1;
                if let Some(&(_, sent_at)) = hops.get(idx) {
                    let is_truly_final = is_final && src == IpAddr::V4(target_ip);
                    stash.insert(seq as u8, (src, sent_at, is_truly_final, rx_time));
                    received += 1;

                    while let Some((a, s, fin, rt)) = stash.remove(&next_ttl) {
                        let elapsed = rt - s;
                        println!("{:<ttl_w$} {:<ip_w$} {:.2?}", next_ttl, a, elapsed,
                                 ttl_w = 3, ip_w = 16);
                        next_ttl += 1;
                        if fin { drop(handle); return Ok(()); }
                    }

                    if received >= count { break; }
                }
            }
            Ok(None) => break,
            Err(_elapsed) => {
                println!("{} *", next_ttl);
                break;
            }         
        }
    }

    drop(handle);
    Ok(())
}

// // NOT libpcap WITH unix // //

/// Creates a thread to listen for echo replies.
#[cfg(not(feature = "with-libpcap"))]
async fn rx_icmp_packets(
    icmp_iterator: &mut IcmpTransportChannelIterator<'_>,
    timeout_seconds: u64,
    start_times: Vec<Duration>
)-> Result<(), NtkError> {
    // Wait for a response with a timeout
    // next_with_timeout blocks untl a packet is rx or the timeout expires
    match icmp_iterator
        .next_with_timeout(Duration::from_secs(timeout_seconds))
        .map_err(NtkError::IcmpReceive)?
        {
        Some((packet, addr)) => {
            if packet.get_icmp_type() == IcmpTypes::EchoReply {
                if let Some(reply) = EchoReplyPacket::new(packet.packet()) {
                    let seq = reply.get_sequence_number();
                    let idx = seq as usize - 1;

                    if let Some(&sent_at) = start_times.get(idx) {
                        let elapsed = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default() - sent_at;
                        println!("{:<seq_w$} {:<ip_w$} {:.2?}", seq, addr, elapsed,
                                seq_w = 3, ip_w = 16);
                    } else {
                        eprintln!("seq {} out of range", seq);
                    }
                }
            } else if packet.get_icmp_type() == IcmpTypes::TimeExceeded {
                // TimeExceeded (where the number below is the byte offset into the packet (inner request))
                // When TimeExceeded occurs, part of the response is our original EchoRequest
                // We extract the sequence number by grabbing the inner content
                let seq = packet.packet()
                    .get(28..)
                    .map(|inner| {
                        let mut buf = inner.to_vec();
                        MutableEchoRequestPacket::new(&mut buf)
                            .map(|p| p.get_sequence_number())
                    })
                    .flatten();
                if let Some(seq) = seq {
                    let idx = seq as usize - 1;
                    if start_times.get(idx).is_some() {
                        println!("{:<seq_w$} {:<ip_w$} *", seq, addr, seq_w = 3, ip_w = 16);
                    }
                }
            }
        }
        None => {
            // asterisk commonly means timeout or no response
            println!("{} *", 1);
        }
    }
    Ok(())
}

/// Creates a thread to listen for timeout replies.
#[cfg(not(feature = "with-libpcap"))]
async fn rx_tr_packets(
    rx: &mut TransportReceiver,
    hops: Vec<(u8, Duration)>,
    timeout_seconds: u64,
    target_ip: IpAddr
) -> Result<(), NtkError> {
    let mut iter = icmp_packet_iter(rx);
    let count = hops.len();
    let mut received: usize = 0;
    let mut next_ttl: u8 = 1;
    let mut stash: std::collections::HashMap<u8, (std::net::IpAddr, Duration, bool)> = std::collections::HashMap::new();

    loop {
        match iter.next_with_timeout(Duration::from_secs(timeout_seconds)).map_err(NtkError::IcmpReceive)?
        {
            Some((packet, addr)) => {
                let arrived = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let is_final = packet.get_icmp_type() == IcmpTypes::EchoReply && addr == target_ip;

                // Extract TTL from the sequence number
                let seq = if is_final {
                    EchoReplyPacket::new(packet.packet())
                        .map(|r| r.get_sequence_number() as u8)
                } else {
                    // TimeExceeded (where the number below is the byte offset into the packet (inner request))
                    // When TimeExceeded occurs, part of the response is our original EchoRequest
                    // We extract the sequence number by grabbing the inner content
                    packet.packet()
                        .get(28..)
                        .map(|inner| {
                            let mut buf = inner.to_vec();
                            MutableEchoRequestPacket::new(&mut buf)
                                .map(|p| p.get_sequence_number() as u8)
                        })
                        .flatten()
                };

                if let Some(ttl) = seq {
                    let idx = ttl as usize - 1;
                    // Add the response to the hashmap
                    if let Some(&(_, sent_at)) = hops.get(idx) {
                        stash.insert(ttl, (addr, sent_at, is_final));
                        received += 1;

                        // Attempt to drain the map starting from the first sequence number
                        while let Some((a, s, fin)) = stash.remove(&next_ttl) {
                            let elapsed = arrived - s;
                            println!("{:<ttl_w$} {:<ip_w$} {:.2?}", next_ttl, a, elapsed,
                                     ttl_w = 3, ip_w = 16);
                            next_ttl += 1;
                            if fin { return Ok(()); }
                        }

                        if received >= count { break; }
                    }
                }
            }
            None => {
                println!("{} *", next_ttl);
                break;
            }
        }
    }

    Ok(())
}

// // Functions applicable to all

/// Creates an ICMP packet using the pnet crate and sends it to the IP using the provided tx TransportSender
fn send_icmp_packets(ip: Ipv4Addr, seq_number: u8, tx: &mut TransportSender) -> Result<Duration, NtkError> {
    let mut buffer = [0u8; 64];
    let mut packet = MutableEchoRequestPacket::new(&mut buffer)
        .ok_or(NtkError::PacketBufferTooSmall)?;
    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_identifier(u16::try_from(std::process::id()).unwrap_or(0));
    packet.set_sequence_number(seq_number as u16);
    // Without a correct checksum, routers will drop the packet
    packet.set_checksum(
        pnet::packet::icmp::checksum(
            &IcmpPacket::new(packet.packet())
                .ok_or(NtkError::PacketBufferTooSmall)?
            )
        );
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    match tx.send_to(packet, ip.into()) {
        Err(e) => { return Err(NtkError::PacketSendFailure(e)) }
        _ => {}
    };
    Ok(start)
}

/// Runs a ping either with-libpcap or without
pub async fn run_ping(ip_str: &str, timeout_seconds: u8, count: u8, packet_ttl: u8) -> Result<(), NtkError> {
    // Input validation
    let ip = util::str_or_hostname_to_ipv4(ip_str).await;
    // Construct the transport tx+rx
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    #[cfg(feature = "with-libpcap")]
    let (mut tx, _) = transport_channel(1024, protocol)
        .or_else(|e| Err(NtkError::DatalinkOpenFailure(e)))?;

    #[cfg(not(feature = "with-libpcap"))]
    let (mut tx, mut rx) = transport_channel(1024, protocol)
        .or_else(|e| Err(NtkError::DatalinkOpenFailure(e)))?;

    // Set the time-to-live of the packets
    tx.set_ttl(packet_ttl)
        .or_else(|e| Err(NtkError::PacketTtlSetFailure(e)))?;

    // Setup the rx thread if needed for the target OS
    // We gate the functions behind features on/off and target OS to prevent borrow errors
    #[cfg(feature = "with-libpcap")]
    let join_handle_option = setup_rx_ping(ip, timeout_seconds as u64).await?;

    // Vector to hold the start times
    let mut start_times: Vec<Duration> = vec!();

    // Send the packets
    for sequence in 1..=count {
        start_times.push(send_icmp_packets(ip, sequence, &mut tx)?);
        // tokio::time::sleep(Duration::from_secs(1)).await; // delays the start time of each packet in the sequence when used
    }

    // println!("DEBUG: Finshed sending packets at: {:?}! Awaiting response...", Instant::now());

    // Monitor Rx of the packet in a cross-platform way
    #[cfg(feature = "with-libpcap")]
    rx_icmp_packets(timeout_seconds as u64, start_times, join_handle_option).await?;

    #[cfg(not(feature = "with-libpcap"))]
    rx_icmp_packets(&mut icmp_packet_iter(&mut rx), timeout_seconds as u64, start_times).await?;
    Ok(())
}

/// Runs a traceroute either with-libpcap or without
pub async fn run_traceroute(ip_str: &str, timeout_seconds: u8, packet_ttl: u8) -> Result<(), NtkError> {
    // Setup the tx and rx channels
    let ip = util::str_or_hostname_to_ipv4(ip_str).await;
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    #[cfg(not(feature = "with-libpcap"))]
    let (mut tx, mut rx) = transport_channel(1024, protocol)
        .or_else(|e| Err(NtkError::DatalinkOpenFailure(e)))?;

    #[cfg(feature = "with-libpcap")]
    let (mut tx, _) = transport_channel(1024, protocol)
        .or_else(|e| Err(NtkError::DatalinkOpenFailure(e)))?;

    #[cfg(feature = "with-libpcap")]
    let handle = setup_rx_traceroute(ip, timeout_seconds as u64).await?;

    // Step through packet TTLs (we will break if we rx a reply earlier)
    let mut hops: Vec<(u8, Duration)> = Vec::new();
    for ttl in 1..=packet_ttl {
        tx.set_ttl(ttl)
            .or_else(|e| Err(NtkError::PacketTtlSetFailure(e)))?;
        let start_time = send_icmp_packets(ip, ttl, &mut tx)?;
        hops.push((ttl, start_time));
    }

    #[cfg(not(feature = "with-libpcap"))]
    {
        rx_tr_packets(&mut rx, hops, timeout_seconds as u64, ip.into()).await?
    }

    #[cfg(feature = "with-libpcap")]
    {
        rx_tr_packets(handle, hops, timeout_seconds as u64, ip).await?
    }
    Ok(())
}
