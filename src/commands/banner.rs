use crate::error::NtkError;
use crate::scan_util::{banner_ports};

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use std::time::{Duration};
use std::net::{Ipv4Addr};

async fn connect_for_banner(ip: &str, port: u16) -> Option<String> {
    // Combine the IP and port into a socket address string
    let address = format!("{}:{}", ip, port);

    // Attempt to connect to the address
    let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(&address))
        .await
    {
        Ok(Ok(s)) => s, // One Ok for timeout and another for TcpStream::connect to unwrap the stream
        _ => return None,
    };

    // HTTP / HTTPS requires a 'probe' to invoke a banner response (pull based protocol)
    match port {
        80 | 443 | 8080 => {
            if stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.is_err() {
                return None
            }
        }
        _ => {}
    };

    // Grab the banner from the TCP stream
    let mut buf = vec![0u8; 1024];
    match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
        }
        _ => None,
    }
}

pub async fn run(target_ip: Ipv4Addr) -> Result<(), NtkError> {
    for port in banner_ports() {
        match connect_for_banner(&target_ip.to_string(), port).await {
            Some(banner_string) => {
                println!("{:<port_w$}: '{}'", port, banner_string, port_w = 5);
            }
            None => {
                println!("{:<port_w$}: No banner found.", port, port_w = 5);
            }
        }
    }
    Ok(())
}
