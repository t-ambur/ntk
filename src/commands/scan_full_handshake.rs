use crate::scan_util::{PortIter, port_map};
use crate::error::NtkError;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use std::sync::Arc;

use std::time::{Duration};
use std::net::{Ipv4Addr};


const MAX_CONCURRENT: usize = 1000;


// Function to 'scan' a single port by attempting a full TCP handshake
async fn full_tcp_handshake_port(ip: &str, port: u16) -> Option<u16> {
    // Combine the IP and port into a socket address string
    let address = format!("{}:{}", ip, port);

    // Attempt to connect to the address
    match timeout(Duration::from_secs(5), TcpStream::connect(&address)).await {
        Ok(_) => { Some(port) } // If the connection succeeds, the port is open
        _ => { None }
    }
}

// Convience function for outputing scan results across the various functions
fn print_port(port: u16, lookup_name: bool) {
    if lookup_name {
        let common_name = port_map().get(&port).unwrap_or(&"Unknown");
        println!("{port}: {common_name}");
    } else {
        println!("{port}");
    }
}

pub async fn run_tcp_handshake(target_ip: Ipv4Addr, lookup_name: bool, delay: u64, start_range: Option<u16>, end_range: Option<u16>) -> Result<(), NtkError> {
    let ip = target_ip.to_string();
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut join_set = JoinSet::new();

    for port in PortIter::new(start_range, end_range) {
        let ip = ip.clone();
        let sem = semaphore.clone();
        let permit = sem.acquire_owned()
            .await
            .or_else(|e| Err(NtkError::SemaphoreAquirePermitFailure(e)))?;
        join_set.spawn(async move {
            let result = full_tcp_handshake_port(&ip, port).await;
            drop(permit); // release back to semaphore when task completes
            result
        });

        // Drain completed semaphore permits to avoid deadlock
        while let Some(result) = join_set.try_join_next() {
            if let Ok(Some(port)) = result {
                print_port(port, lookup_name);
            }
        }

        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    // Print results as tasks complete rather than waiting for all of them
    while let Some(result) = join_set.join_next().await {
        if let Ok(Some(port)) = result {
            print_port(port, lookup_name);
        }
    }

    Ok(())
}