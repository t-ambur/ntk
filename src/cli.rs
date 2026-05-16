use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ntk")]
#[command(author = "Trevor Amburgey")]
#[command(version = "0.3.1")]
#[command(about = "Network Toolkit - Cross-platform network diagnostics")]
#[command(infer_subcommands = true)]
#[command(infer_long_args = true)]
#[command(help_template = "\
{about}
By {author}
v{version}

{usage-heading} {usage}

{all-args}
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Perform a check of layers 1-4 and 7 for a given IP or hostname by running most of the commands in ntk
    Analyze {
        /// The IP 
        ip: String,

        /// When true will lookup/query the MAC address vendor online
        #[arg(short, long, default_value_t = false,)]
        web_lookup_mac: bool,

        /// Ignore certificate checking similar to curl -k (insecure)
        #[arg(short, long, default_value_t = false, visible_short_alias = 'k')]
        ignore_certs: bool,

        /// Use HTTP instead of HTTPS when running L7 fetch analysis
        #[arg(short, long, default_value_t = false)]
        use_http: bool,
    },
    /// Discover IP and MAC addresses adjacent to this machine using ARP
    Discover {
        /// A specific network interface to use (e.g., eth0, wlan0)
        #[arg(short, long)]
        interface: Option<String>,

        /// How long to wait for ARP replies
        #[arg(short, long, default_value_t = 2)]
        collection_time: u64
    },
    /// Perform an HTTP GET on the provided URL or IP Address
    Fetch {
        /// The URL or IP Address to GET
        url: String,

        /// Don't display the GET payload response but still show the status codes and redirects
        #[arg(short, long, default_value_t = false, conflicts_with = "download")]
        no_content: bool,

        /// Ignore certificate checking similar to curl -k (insecure)
        #[arg(short, long, default_value_t = false, visible_short_alias = 'k')]
        ignore_certs: bool,

        /// Use HTTP instead of HTTPS when not provided at the front of the URL to GET
        #[arg(short, long, default_value_t = false)]
        use_http: bool,

        /// Save the remote URL as a file on this machine similar to curl -O
        #[arg(short, long, default_value_t = false, conflicts_with = "no_content", visible_short_alias = 'O')]
        download: bool,

        /// A location to save a download or GET request to a file
        #[arg(long, visible_short_alias = 'o', visible_alias = "filepath")]
        download_path: Option<String>,

        /// Show all the header values from the response
        #[arg(short, long, default_value_t = false, visible_short_alias = 'I')]
        show_headers: bool,

        /// How many redirects to follow before stopping (the max amount)
        #[arg(long, default_value_t = 10)]
        num_hops: u8,
    },
    /// Displays the default network interface and gateway on this device
    Gateway {
        /// Show only the first match for gateways
        #[arg(short, long, default_value_t = false)]
        first_match: bool,

        /// Show only the default gateways instead of the route string
        #[arg(short, long, conflicts_with = "interface_only", default_value_t = false)]
        gateways_only: bool,

        /// Show only the default interface instead of the route string
        #[arg(short, long, conflicts_with = "gateways_only", default_value_t = false)]
        interface_only: bool,
    },
    /// List all interfaces, IP+MAC Addresses, and their states on this device
    Interface {
        /// Show only interfaces that are DOWN (unavailable)
        #[arg(short, long, conflicts_with = "up_only", default_value_t = false)]
        down_only: bool,

        /// Show only interfaces that are UP (available)
        #[arg(short, long, conflicts_with = "down_only", default_value_t = false)]
        up_only: bool,
    },
    /// Lookup the DNS name for a provided IP (or vice-versa)
    Lookup {
        /// The IPv4 address or hostname lookup
        ip: String,

        /// Convert a DNS hostname back into an IP
        #[arg(short, long)]
        name_lookup: bool
    },
    /// Performs a HTTP 'Fetch' (GET) to determine the vendor of a provided MAC Address (e.g. FF:FF:FF)
    MacVendor {
        /// At least the first three octets of a MAC Address to identify (OUI)
        address: String,

        /// Ignore certificate checking similar to curl -k (insecure)
        #[arg(short, long, default_value_t = false, visible_short_alias = 'k')]
        ignore_certs: bool,
    },
    /// Ping (or optionally trace) a provided IP using ICMP
    Ping {
        /// The IPv4 address to ping
        ip: String,

        /// Trace the ping route using TTL
        #[arg(short, long)]
        trace: bool,

        /// Adjusts how many packets are sent for a ping in one batch (does not apply to trace)
        #[arg(short, long, default_value_t = 1)]
        count: u8,

        /// How long the packets should live before expiring
        #[arg(long, default_value_t = 10)]
        packet_ttl: u8,

        /// How long to wait (in seconds) for replies before exiting
        #[arg(long, default_value_t = 10)]
        timeout: u8,
    },
    /// Reveal open ports on a provided IP by attempting connections to them
    Scan {
        /// The IPv4 address to scan for open TCP sockets
        ip: String,

        /// Lookup the matched port numbers via hash and output a common name if known
        #[arg(short, long, default_value_t = false)]
        lookup_name: bool,

        /// Show the ports that responded as (RST) during a SYN probe (likely closed)
        #[arg(short, long, default_value_t = false)]
        reset: bool,

        /// How long to wait (in milliseconds) in-between connection attempts
        #[arg(short, long, default_value_t = 10)]
        delay: u64,

        /// An optional starting port number to scan all ports from this port number up (inclusive)
        #[arg(short, long)]
        start_range: Option<u16>,

        /// An optional ending port number to scan all ports up to this port number (inclusive)
        #[arg(short, long)]
        end_range: Option<u16>,

        /// How long to wait (in seconds) for replies before exiting (doesn't apply for full handshake test)
        #[arg(long, default_value_t = 10)]
        timeout: u8,

        /// When true, replace the default SYN probe with ACK instead
        #[arg(short, long, default_value_t = false, conflicts_with = "full_handshake")]
        ack_probe: bool,

        /// When true, replace the ACK probe packet with a FIN flag instead
        #[arg(long, default_value_t = false, conflicts_with = "full_handshake")]
        fin_probe: bool,

        /// When true, replace the default SYN probe with a full TCP handshake per port
        #[arg(short, long, default_value_t = false, conflicts_with = "ack_probe")]
        full_handshake: bool,

        /// When provided: use this port as the source for the SYN probe instead of a random one
        #[arg(long)]
        source_port: Option<u16>
    }    
}