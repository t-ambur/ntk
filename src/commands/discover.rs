use std::net::IpAddr;

pub fn run(interface: &str, subnet: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Discovering devices on Interface: {}...", interface);
    
    // TODO: Parse subnet and iterate IPs
    // TODO: Send ICMP ping to each
    // TODO: Collect responses
    
    println!("[*] Discovery complete");
    Ok(())
}