use std::{fmt};

use tokio::sync::AcquireError;

#[derive(Debug)]
pub enum NtkError {
    DnsLookup(std::io::Error),
    DnsResolve(std::io::Error),
    NetDevGatewayFailure(String),
    NetDevDefaultInterfaceFailure(String),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    IfNameNotFound(String),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    IfNameHasNoAssignedIps(String),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    SourceMacAddressFailure(String),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    DatalinkOpenFailure(std::io::Error),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    DatalinkUnsupportedChannel,
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    Ipv6FoundError,
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    PacketBufferTooSmall,
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    PacketSendFailure(std::io::Error),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    PacketTtlSetFailure(std::io::Error),
    FetchFileCreationError(std::io::Error),
    FetchFileWriteError(std::io::Error),
    FetchFailedToGetJson(reqwest::Error),
    FetchFailedToGetTextBody(reqwest::Error),
    FetchResponseFailure(reqwest::Response),
    ReqwestClientBuildFailure(reqwest::Error),
    ReqwestSendFailure(reqwest::Error),
    HttpGetChunkFailure(reqwest::Error),
    HttpHeaderToStringFailure(reqwest::header::ToStrError),
    UrlParseFailure(url::ParseError),
    SemaphoreAquirePermitFailure(AcquireError),
    #[cfg(feature = "with-libpcap")]
    GatewayResolutionFailure(String),
    #[cfg(feature = "with-libpcap")]
    GatewayMacUnresolved,
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    ArpResolutionTimeout(String),
    #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
    #[allow(dead_code)]
    IcmpReceive(std::io::Error),
    #[cfg(all(not(unix), not(feature = "with-libpcap")))]
    WrongBinaryInUse(String),
    IpIfAssociationError(String),
    #[cfg(feature = "with-libpcap")]
    LibPacketCaptureFailure(pcap::Error),
    #[cfg(feature = "with-libpcap")]
    TaskJoinError,
    #[cfg(feature = "with-libpcap")]
    UnexpectedHandle,
    JsonParseFailure(serde_json::Error),
}

impl fmt::Display for NtkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtkError::DnsLookup(e) => write!(f, "DNS lookup of IP address failed: {e}"),
            NtkError::DnsResolve(e) => write!(f, "DNS resolution of hostname to IP failed: {e}"),
            NtkError::NetDevGatewayFailure(s) => write!(f, "Failed to find the default gateway: {s}"),
            NtkError::NetDevDefaultInterfaceFailure(s) => write!(f, "Failed to find the default interface: {s}"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::IfNameNotFound(s) => write!(f, "No interface exists with the name: {s}"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::IfNameHasNoAssignedIps(s) => write!(f, "Interface name does not have any IPv4 addresses assigned to it: {s}"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::SourceMacAddressFailure(s) => write!(f, "Was unable to find a MAC address for interface with name: '{s}'"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::DatalinkOpenFailure(e) => write!(f, "Failed to open datalink channels for transmit and receive: {e}"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::DatalinkUnsupportedChannel => write!(f, "Unexpected datalink channel provided while trying to open transmit and receive channels."),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::Ipv6FoundError => write!(f, "Found an IPv6 while trying to process IPv6 data, which is unexpected an unhandled by ntk."),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::PacketBufferTooSmall => write!(f, "Buffer provided was too small to construct ethernet packet."),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::PacketSendFailure(e) => write!(f, "Failed to send packet through the transmit channel: {e}"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::PacketTtlSetFailure(e) => write!(f, "Failed to set the TTL (time to live) of the packet: {e}"),
            NtkError::FetchFileCreationError(e) => write!(f, "Failed to create a file on the operating system to store the fetch data in: {e}"),
            NtkError::FetchFileWriteError(e) => write!(f, "Failed to write the fetch data to the provided file path: {e}"),
            NtkError::FetchFailedToGetJson(e) => write!(f, "Failed to get or deserialize the JSON body from the response: {e}"),
            NtkError::FetchFailedToGetTextBody(e) => write!(f, "Failed to get the text body from the response: {e}"),
            NtkError::FetchResponseFailure(resp) => write!(f, "Unsuccessful response code from remote server: '{}', reason: '{}'", resp.status().as_str(), resp.status().canonical_reason().unwrap_or("Unknown")),
            NtkError::ReqwestClientBuildFailure(e) => write!(f, "Failed to build HTTP (reqwest) client required to send request: {e}"),
            NtkError::ReqwestSendFailure(e) => write!(f, "Failed to send HTTP request using (reqwest) client: {e}"),
            NtkError::HttpGetChunkFailure(e) => write!(f, "Failed to get/collect download chunk: {e}"),
            NtkError::HttpHeaderToStringFailure(e) => write!(f, "Failed to convert HTTP header to a string: {e}"),
            NtkError::UrlParseFailure(e) => write!(f, "Failed to parse URL: {e}"),
            NtkError::SemaphoreAquirePermitFailure(e) => write!(f, "A thread failure to acquire a lock required to perform work: {e}"),
            #[cfg(feature = "with-libpcap")]
            NtkError::GatewayResolutionFailure(s) => write!(f, "Unable to find the default gateway on the interface in order to send packets: {s}"),
            #[cfg(feature = "with-libpcap")]
            NtkError::GatewayMacUnresolved => write!(f, "The default gateway was detected but its MAC Address is 'the zero address' and is unusable as a destination."),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::ArpResolutionTimeout(s) => write!(f, "Timeout waiting for an ARP reply from a remote IP: {s}"),
            #[cfg(not(all(target_os = "windows", not(feature = "with-libpcap"))))]
            NtkError::IcmpReceive(e) => write!(f, "Failed to receive ICMP ping packet: {e}"),
            #[cfg(all(not(unix), not(feature = "with-libpcap")))]
            NtkError::WrongBinaryInUse(s) => write!(f, "{s}"),
            NtkError::IpIfAssociationError(s) => write!(f, "No interface exists with the assigned source IP: {s}"),
            #[cfg(feature = "with-libpcap")]
            NtkError::LibPacketCaptureFailure(e) => write!(f, "Failure to receive or setting up to receive packets: {e}"),
            #[cfg(feature = "with-libpcap")]
            NtkError::TaskJoinError => write!(f, "Failed to gracefully join (shutdown) async thread."),
            #[cfg(feature = "with-libpcap")]
            NtkError::UnexpectedHandle => write!(f, "A function expected a thread handle or an async tokio handle but rx the wrong one."),
            NtkError::JsonParseFailure(e) => write!(f, "Failed to parse JSON: {e}"),
        }
    }
}

impl std::error::Error for NtkError {}