# Overview

Network ToolKit (ntk) is a cross-platform networking discovery and diagnostic Command Line Interface (CLI) tool written entirely in Rust. It contains all the basic functionality that you would need to troubleshoot a network from a combination of common linux binaries, such as: _ip addr show_, _ip route show default_, _arpscan_, _ping_, _traceroute_, _nslookup_, _nmap_, and _curl_. Vendor lookups can also be performed on MAC addresses against hardcoded online databases. The functionality bundled into `ntk` enables troubleshooting at layers 1-4 and 7 of [the OSI model](https://www.geeksforgeeks.org/computer-networks/open-systems-interconnection-model-osi/).

One of the primary benefits of bundling so many functionalities together is the ability to execute many of these functionalites from within a single subcommand. Network ToolKit provides the `ntk analyze` subcommand to peform a connectivity check from layers 2 through 4 and 7. Layer 1 interface information will also be output to the terminal for this machine.

The `ntk` binary is many times smaller in size than all of these other comparable binaries combined on Linux and the output of each subcommand of `ntk` is greatly simplified to make it easy to find the information you commonly need. As a cross-platform tool, the output on Windows is designed to look as close as possible to the output on Linux. This eliminates the need to learn a whole new combination of commands on Windows if you are familiar with ntk on Linux.


`ntk help`
```
Network Toolkit - Cross-platform network diagnostics
By Trevor Amburgey
v0.1.0

Usage: ntk <COMMAND>

Commands:
  analyze     Perform a check of layers 1-4 and 7 for a given IP or hostname by running most of the commands in ntk
  discover    Discover IP and MAC addresses adjacent to this machine using ARP
  fetch       Perform an HTTP GET on the provided URL or IP Address
  gateway     Displays the default network interface and gateway on this device
  interface   List all interfaces, IP+MAC Addresses, and their states on this device
  lookup      Lookup the DNS name for a provided IP (or vice-versa)
  mac-vendor  Performs a HTTP 'Fetch' (GET) to determine the vendor of a provided MAC Address (e.g. FF:FF:FF)
  ping        Ping (or optionally trace) a provided IP using ICMP
  scan        Reveal open ports on a provided IP by attempting connections to them
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

# Disclaimer

Network ToolKit is not intended to replace any individual binary on either Unix nor Windows. Network ToolKit's goal is to provide the absolute basic, must-need functionality to someone who needs to troubleshoot or perform network discovery tasks. I assume no liability for any potential malfunction or damage to networking devices you interact with as a result of executing `ntk` (including both the sending and receiving device(s)).

For more information on reuse and liability, please see the **LICENSE** and **NOTICE** files in the root of this repository.

# Windows System For Linux

You can run `ntk` using the binaries compiled for Linux in WSL2 but [you should have enabled 'mirroring' networkingMode between WSL2 and the Windows Host](https://windowsforum.com/threads/wsl-networking-in-windows-11-mirrored-mode-and-dns-tunneling-guide.386779/#-how-to-enable-mirrored-networking-two-ways).

Please note I have noticed some inconsistency with the ability to run the `ntk scan` command form within WSL2 due to the way the Windows host intercepts the packets before they reach the contained Linux instance of WSL2. Windows firewall and routing rules may also cause issues with receiving packets in WSL2. I would recommend using the with-libpcap (_npcap_) compiled version of the `ntk.exe` for Windows instead. [See the next section on dependencies for more information on with-libpcap/_npcap_](#dependencies).

# Dependencies

Network ToolKit has an optional dependency on libpcap on Unix/Linux (including WSL2 distros). For most GNU based distributions: libpcap isn't required at all for `ntk` to function in its entirety.

On **Windows**, it is **highly recommended you install npcap** with API-compatible mode enabled in order to get the full packet transmit and receive capabilities. You [can install npcap with a Windows installer here](https://npcap.com/#download). Choose **Npcap x.yy installer** and be sure to select the checkbox for **WinPcap API-compatible mode** when clicking through the installer window. Many the subcommands will not function on Windows without _npcap_ (i.e. 'native' `ntk`) and the with-libpcap compiled version of `ntk` will not execute unless _npcap_ is installed. If you are familiar with the product _Wireshark_ this (_npcap_) is the same backend packet management library that enables _Wireshark_ to analyze packets on Windows.

To keep the binary as flexible and portable as possible, `ntk` can be compiled either with-libpcap (_npcap_ on Windows) or without. The version without libpcap is known as **native** socket `ntk` in the releases page. Please keep this in mind when using pre-built binaries for your operating system.

The with-libpcap compiled versions of `ntk` use different packet transmit and capture options than the 'native' version (this difference is primarily only under the hood). Typically, the with-libpcap compiled versions of `ntk` have more accurate estimations of packet trasmit/receive time and more control over the reception of packets. The 'native' compiled versions of `ntk` may occasionally fight the operating system for reading received packet information from sockets and implies that you may need a greater understanding of the operating system's mechanisms for managing the routing of packets.

# Downloading Pre-Built Binaries

You can download pre-built binaries of `ntk` and `ntk.exe` on the [releases page here on GitHub](https://github.com/t-ambur/ntk/releases). These binaries are built via workflows attached to this repository. Please use the latest version that is available. All of the releases for each version are compressed with the target operating system and the feature set used (either **native** or **pcap**).

## Which Binary is for my Operating System

The `ntk` and `ntk.exe` binaries are compressed into descriptive archive names in the form **ntk-{Binary Name}-{feature}**. For Mac you will have to choose _intel_ or _arm_ depending on your CPU architecture. For Linux you will have to choose GNU or musl. All binaries are **x86_64** unless the word _arm_ appears in the archive name. Use the following table to determine which 'Binary Name' corresponds to your operating system:

| OS Name  | Binary Name |
|----------|-------------|
| Windows  | windows     |
| Mac OS   | macos       |
| Ubuntu   | linux-gnu   |
| Debian   | linux-gnu   |
| RHEL     | linux-gnu   |
| Oracle L | linux-gnu   |
| Alpine   | linux-musl  |

This table is not all inclusive. For Linux users, your distro of choice is likely one of GNU or musl. If not, you will have to [compile from source using cargo](#compiling).

I am happy to accept any Pull Requests (PRs) into this repo that add additional build jobs for missing architecture/OS combinations. Please first ensure that you have built from source and tested `ntk` on that distro before submitting a PR for the build pipeline file (_.github/workflows/release.yml_). Also ensure your PR updates this table to inform users which binary they should use on that operating system.

## Should I Use Native or Pcap

Use **ntk-{Binary Name}-native** if your concern is portability and/or use on systems where a libpcap equivalent is unavailable or not installed. This portable version works very well on Ubuntu because GNU linux has excellent support for raw/native socket usage. This **native** socket usage compiled version of `ntk` was the originally envisioned version of Network ToolKit.

Use **ntk-{Binary Name}-pcap** if you want more accurate packet capture support (e.g. packet route timing) or all of the features to be available on Windows. The _native_ binary for Windows **does NOT** contain all the functionality of `ntk.exe`. You must [install npcap in API compatable mode on Windows](#dependencies) or live with using a subset of the functionality `ntk.exe`. This requirement is simply because Windows native socket support is nearly non-existant if you wish to directly manipulate packets.

**NOTE:** I'm re-iterating this warning from [the dependencies](#dependencies) section because its important:
The 'native' compiled versions of `ntk` may occasionally fight the operating system for reading received packet information from sockets and implies that you may need a greater understanding of the operating system's mechanisms for managing the routing of packets. This is the price of portability, unfortunately. If this is a major concern to you, use the **pcap** compiled version of the binary.

## Extracting and Installing the Downloaded Binary

To extract/install on Unix/Linux, from a shell:
```bash
# cd to the download location of ntk-archive-name.tar.gz then
# replace '-archive-name' with the name of your downloaded binary
tar -xf ntk-archive-name.tar.gz

# the binary will be extracted standalone, e.g.:
ls -l ntk
# -rwxr-xr-x 1 trevor trevor 10879064 May  2 22:08 ntk

# Mark the file as executable for all users
chmod a+x ntk

# Optionally, copy to a location on the $PATH
# e.g.:
sudo cp ntk /usr/bin/
# Ensure the binary is executable from the $PATH
ntk

# IMPORTANT
# Give the binary raw socket permissions without needing sudo
# Use ./ntk if you didn't move the file to /usr/bin/ntk
sudo setcap cap_net_raw+ep /usr/bin/ntk
```

To extract on Windows, from powershell:
```ps1
# cd to the download location of ntk-archive-name.tar.gz then
# replace '-archive-name' with the name of your downloaded binary
Expand-Archive -Path "ntk-archive-name.zip" -DestinationPath .

# Ensure the file is executable
# If nothing happens, ensure you installed npcap as described in the 'Dependencies' section of this document
.\ntk.exe

# Optionally, copy the binary into a common $PATH location for your Windows user:
cp ntk.exe $env:LOCALAPPDATA\Microsoft\WindowsApps
# Upon exiting powershell and opening a new one, the ntk/ntk.exe command should be available
# IMPORTANT: ntk.exe must be executed from an administrator elevated powershell
# Test the command executes from your $PATH:
ntk
```

# Executing ntk

Network ToolKit is executed on a command line using a shell command to your operating system. This guide was written using _bash_ on _Ubuntu_ and _powershell_ on _Windows 11_. The letter **x** appears in the documentation of the execution of subcommands to denote arbitrary input (e.g. an IP address, MAC address, URL, etc.)

**NOTE:** The 'Examples' subsection of each command will list which operating system the output (stdout) is from. This does not imply that particular command can only be ran on that operating system. All commands are intended for use on every support operating system (so long as the libpcap equivalent is satisfied or the host is a Unix based operating system (GNU or musl)).

## Binary Setup

First, [download the pre-built binary of your choice for your operating system](#downloading-pre-built-binaries).

Place the binary in the desired location on your filesystem. For Unix/Linux, you will want to give the binary raw socket permissions to avoid using sudo. On Windows, you will want to execute the `ntk.exe` binary from an **administrator** enabled _powershell_ shell.

If you already executed this step in the previous section on extracting the archive, then you do not need to perform this step again. This step must be performed **AFTER EACH TIME THE ntk BINARY MOVES** on the filesystem on Linux (e.g. if you executed it against ./ntk but then copied or moved ntk to /usr/bin/ntk you would have to execute this command against /usr/bin/ntk still).
```bash
# Unix/Linux Only
# Ensure you are in the same directory as the ntk binary
# Or provide the path to ntk
sudo setcap cap_net_raw+ep ntk

# Alpine users may need to install libcap
```

The rest of this section of the documentation on execution will reference the Network ToolKit binary as `ntk`. If you are on **Windows**, you may need to substitute usage of this command with `ntk.exe` instead. Please remember to add the path suffix if the binary is not in a _$PATH_ location (e.g. `./ntk` or `.\ntk.exe`).

## Subcommand Inference

Network Toolkit has an extensive help menu enabled by the [clap crate](https://crates.io/crates/clap). Any of the subcommands listed via `ntk -h` can be shortened using built-in inference.

For example, you could run an ARP discovery on all interfaces by running `ntk discover` or you could simply type `ntk d`. Both subcommands are equivalent.

## Help Menu

You can get the full list of subcommands in `ntk` by executing `ntk -h`. Each subcommand has an additional help menu describing the usage, optional arguments, and default values of the arguments.

For example, via `ntk -h` you could see a subcommand named **ping** is available. Using either the full subcommand name or [inference](#subcommand-inference) you can execute `ntk ping -h` to see the help menu for the **ping** subcommand.

See [the Ping section for a snippet of this help menu](#ping).

## Analyze

The `ntk analyze x` subcommand is best understood as combination of most of the other subcommands included in Network ToolKit. It enables to perform a connectivity test to a remote IP 'x' at layers 2, 3, 4, and 7. It will also print layer 1 interface information for this machine initiating the test (e.g. which interface the test is being run over and information about that interface).

For a given IP 'x', this subcommand executes:
- Show the interface this test is being transmitted out of
- If in the same subnet, send a single ARP request packet to 'x' (not the whole subnet)
    - When `--web-lookup-mac` is provided to this subcommand: performs a layer 7 fetch of the vendor name for the MAC Address
- Show the network prefix CIDR for the target IP if known
- Ping the remote target IP x
- Traceroute the remote target IP x
- Perform a TCP SYN probe scan of target IP x (Unix or with-libpcap/npcap only)
    - A 'full TCP handshake' is executed on Windows instead when using the exe compiled without libpcap/npcap (native)
- A DNS lookup of the hostname for target IP x
- A HTTPS fetch (GET) of port 443 for target IP x (with flag --no-content)

For more information on each of these individual functionalities of `ntk`, please see the respective section in the documentation below this section.

`ntk analyze -h`
```
Perform a check of layers 1-4 and 7 for a given IP or hostname by running most of the commands in ntk

Usage: ntk analyze [OPTIONS] <IP>

Arguments:
  <IP>  The IP

Options:
  -w, --web-lookup-mac  When true will lookup/query the MAC address vendor online
  -i, --ignore-certs    Ignore certificate checking similar to curl -k (insecure) [aliases: -k]
  -u, --use-http        Use HTTP instead of HTTPS when running L7 fetch analysis
  -h, --help            Print help
```

### Examples

Some output information here obfuscated or modified for ambiguity of my devices.
The formatting and error messages are unchanged.

Example 1 (Linux or WSL2):  
Analyzing the home router on my local subnet:  
`ntk analyze 10.0.0.1 -w -i`
```
Running analyze against IP: '10.0.0.1'

L1:
Origin interface is 'eth1' with MAC '00:00:00:00:00:00' and IP '10.0.0.136' with prefix '/24'
Origin Interface is 'UP'

L2:
Target IP is located in the same subnet as the origin IP. Performing ARP request...
Target IP has MAC address: 'aa:aa:aa:aa:aa:aa'
Vendor lookup result (HTTP): Vantiva USA LLC

L3:
Target IP is: '10.0.0.1/24'
Pinging: '10.0.0.1'...
1   10.0.0.1         2.67ms

Tracing route to: '10.0.0.1' ...
1   10.0.0.1         2.70ms

L4:
Performing TCP SYN probe of: '10.0.0.1' ...
80: HTTP
...

L7:
Performing DNS lookup of: '10.0.0.1'...
Failed to perform DNS lookup: DNS lookup of IP address failed: failed to lookup address information: Name or service not known

Performing HTTP fetch --no-content redirect test against 'https://10.0.0.1' ...

Request #1 to URL: https://10.0.0.1
200
(No redirects)
```

Example 2 (Linux or WSL2):  
Analyzing a remote IP from the internet:  
`ntk analyze 8.8.8.8 -w` 
```
 ./ntk analyze 8.8.8.8 -w
Running analyze against IP: '8.8.8.8'

L1:
Origin interface is 'eth1' with MAC '00:00:00:00:00:00' and IP '10.0.0.136' with prefix '/24'
Origin Interface is 'UP'

L2:
Target IP is not on the same subnet as the origin IP. An ARP scan will not reveal the MAC address of this machine.

L3:
Target IP is: '8.8.8.8'
Pinging: '8.8.8.8'...
1   8.8.8.8          10.18ms

Tracing route to: '8.8.8.8' ...
1   10.0.0.1         2.15ms
2   10.27.13.195     4.56ms
3   68.85.152.81     4.56ms
4   69.139.192.221   4.89ms
5   68.86.211.113    4.89ms
6   68.85.159.161    6.98ms
7   69.241.64.98     9.58ms
8   142.251.249.121  9.98ms
9   142.250.224.245  9.98ms
10  8.8.8.8          9.98ms

L4:
Performing TCP SYN probe of: '8.8.8.8' ...
53: DNS
443: HTTPS

L7:
Performing DNS lookup of: '8.8.8.8'...
dns.google
DNS hostname: dns.google

Performing HTTP fetch --no-content redirect test against 'https://8.8.8.8' ...

Request #1 to URL: https://8.8.8.8
302
Redirect -> https://dns.google/

Request #2 to URL: https://dns.google/
200
```

## Discover

The `ntk discover` subcommand is used to find devices directly adjacent to one or more of the network interfaces on your computer. Discover uses an ARP scan broadcast to ask other devices on the network to reveal their MAC addresses based on the concept of 'who has x.x.x.x IP Address'. This results in both layer 2 (MAC) and layer 3 (IP) information for your subnet. Please note that some devices will mask their actual internal MAC Address in response to this scan for their own protection (and will return a different one instead).

When executed without an argument, `ntk discover` will attempt to scan each interface on your computer one by one to find adjacent devices. You can alternatively only scan a specific interface with `ntk d -i interface_name`. Please note that on Windows either the 'friendly name' (first) or the GUID (second) can be specified. Be sure to extend the `--collection-time` (in seconds) if you want to wait longer for devices to reply.

You can find the interfaces on your current device [using the interface subcommand](#interface).

`ntk discover -h`
```
Discover IP and MAC addresses adjacent to this machine using ARP

Usage: ntk discover [OPTIONS]

Options:
  -i, --interface <INTERFACE>              A specific network interface to use (e.g., eth0, wlan0)
  -c, --collection-time <COLLECTION_TIME>  How long to wait for ARP replies [default: 2]
  -h, --help                               Print help
```

### Examples

Some output information here obfuscated or modified for ambiguity of my devices.
The formatting and error messages are unchanged.

Example:  
Scanning all interfaces as no `--interface` flag is provided:  
`ntk discover`
```
Scanning all interfaces because --interface was not provided
Skipping loopback interface: lo
Failed to scan interface: Interface name does not have any IPv4 addresses assigned to it: eth0
Skipping loopback interface: loopback0
[*] Discovering devices on Interface: 'eth1' ...
IP               MAC
10.0.0.1         aa:aa:aa:aa:aa:aa
10.0.0.151       aa:aa:aa:aa:aa:aa
10.0.0.158       aa:aa:aa:aa:aa:aa
10.0.0.61        aa:aa:aa:aa:aa:aa
10.0.0.163       aa:aa:aa:aa:aa:aa
10.0.0.25        aa:aa:aa:aa:aa:aa
10.0.0.181       aa:aa:aa:aa:aa:aa
10.0.0.74        aa:aa:aa:aa:aa:aa
10.0.0.178       aa:aa:aa:aa:aa:aa
10.0.0.102       aa:aa:aa:aa:aa:aa
10.0.0.152       aa:aa:aa:aa:aa:aa
[*] Discovery complete for eth1
```

## Fetch

The `ntk fetch x` subcommand retrieves content at layer 7 (application) by executing a HTTPS GET request against a remote target URL or IP. As a troubleshooting tool, `ntk fetch x` will execute a separate GET command against each redirect returned by the server. This is extremely useful for figuring out if you lose connectivity at a particular 'hop' over HTTPS.

The most notable uses of this command are:
- `--no-content` to simply confirm that you can connect to each hop at the application layer
- `--show-headers` to see the headers for the response from each hop
- `--ignore-certs` commonly used when developing and troubleshooting HTTPS connections
- `--download` to save a remote resource to a file with a progress bar as opposed to outputing to stdout

`ntk fetch -h`
```
Perform an HTTP GET on the provided URL or IP Address

Usage: ntk fetch [OPTIONS] <URL>

Arguments:
  <URL>  The URL or IP Address to GET

Options:
  -n, --no-content                     Don't display the GET payload response but still show the status codes and redirects
  -i, --ignore-certs                   Ignore certificate checking similar to curl -k (insecure) [aliases: -k]
  -u, --use-http                       Use HTTP instead of HTTPS when not provided at the front of the URL to GET
  -d, --download                       Save the remote URL as a file on this machine similar to curl -O [aliases: -O]
      --download-path <DOWNLOAD_PATH>  A location to save a download or GET request to a file [aliases: -o, --filepath]
  -s, --show-headers                   Show all the header values from the response [aliases: -I]
      --num-hops <NUM_HOPS>            How many redirects to follow before stopping (the max amount) [default: 10]
  -h, --help                           Print help
```

### Examples

Example 1:  
Doing what the `ntk fetch` subcommand was created for, a simple redirect test:  
`ntk fetch -i -n 8.8.8.8`
```
Request #1 to URL: https://8.8.8.8
302
Redirect -> https://dns.google/

Request #2 to URL: https://dns.google/
200
```

Example 2:  
Downloading a large file from the internet:  
`ntk fetch -d https://yum.oracle.com/ISOS/OracleLinux/OL10/u1/x86_64/OracleLinux-R10-U1-x86_64-boot-uek.iso`
```
Downloading...   4.88%
(... percentage continues to update until download completes ...)
Downloading... 100.00%
Finished downloading file: OracleLinux-R10-U1-x86_64-boot-uek.iso
```

Tip: by default the `--download` flag will preserve the remote filename of the downloaded file but you could also provide the argument `--download-path` to specify a custom file path for the downloaded file.

## Gateway

The `ntk gateway` subcommand shows the 'default route` to the network gateway for your default network interface. Your **gateway** is typically your first hop on your computers network path and is frequently the router provided by your ISP (Internet Service Provider) at home. Checking gateway connectivity is always a good first step to check connection to the wider network. This information is also frequently needed when setting up static IPs on other devices.

`ntk gateway -h`
```
Displays the default network interface and gateway on this device

Usage: ntk gateway [OPTIONS]

Options:
  -f, --first-match     Show only the first match for gateways
  -g, --gateways-only   Show only the default gateways instead of the route string
  -i, --interface-only  Show only the default interface instead of the route string
  -h, --help            Print help
```

### Examples

Example 1 (Linux or WSL2):  
The 'normal' route string you see on Linux:  
`ntk gateway`
```
'eth1' routes to: '[10.0.0.1]'
```

Example 2 (Windows):  
The 'GUID' of the Windows interface in the Linux style routing string:  
`.\ntk.exe gateway`
```
'{1BFFD6E1-A5C4-47C7-B09B-2E7A6E68899C}' routes to: '[10.0.0.1]'
```

Example 3 (Linux or WSL2):  
Showing only the gateway(s):  
`ntk g -g`
```
[10.0.0.1]
```

Example 4 (Linux or WSL2):  
Showing only the interface that connects to the gateway(s):  
`ntk g -i`
```
eth1
```

## Interface

The `ntk interface` subcommand shows layer 1 information about the networking devices on your computer. This includes their names, MAC Addresses, their state (where UP/DOWN typically means something is connected to them or not), and the IP Address(es) assigned to that interface. On Windows both the 'friendly name' and the GUID of the interface will be displayed.

`ntk interface -h`
```
List all interfaces, IP+MAC Addresses, and their states on this device

Usage: ntk interface [OPTIONS]

Options:
  -d, --down-only  Show only interfaces that are DOWN (unavailable)
  -u, --up-only    Show only interfaces that are UP (available)
  -h, --help       Print help
```

### Examples

Some output information here obfuscated or modified for ambiguity of my devices.
The formatting and error messages are unchanged.

Example 1 (Linux or WSL2):  
All interfaces neatly formatted in a table:  
`ntk interface`
```
eth0       DOWN  aa:aa:aa:aa:aa:aa
eth1       UP    aa:aa:aa:aa:aa:aa  10.0.0.136/24
lo         UP    aa:aa:aa:aa:aa:aa  127.0.0.1/8         10.255.255.254/32
loopback0  UP    aa:aa:aa:aa:aa:aa
```

Example 2 (Windows):  
All interfaces with the 'friendly name' of the interface above each row:  
`.\ntk.exe interface`
```
 Wi-Fi
{1BFFD6E1-A5C4-47C7-B09B-2E7A6E68899C} UP    aa:aa:aa:aa:aa:aa  10.0.0.136/24

 Local Area Connection* 1
{1C15C9E8-6553-44E1-9795-7C9E672B3A65} DOWN  aa:aa:aa:aa:aa:aa  169.254.168.229/16

 Loopback Pseudo-Interface 1
{34EED1B9-F680-11EC-BCF1-806E6F6E6963} UP    aa:aa:aa:aa:aa:aa  127.0.0.1/8

 Ethernet
{36280B7B-9421-4A99-BC92-1DDF11CB01AF} DOWN  aa:aa:aa:aa:aa:aa  10.0.0.129/24

 Local Area Connection* 2
{3FCE202F-0716-41E2-855B-D9856B839CCE} DOWN  aa:aa:aa:aa:aa:aa  169.254.207.145/16

 Bluetooth Network Connection
{A1A7CA3A-D01E-4E81-8F77-2705A084D90C} DOWN  aa:aa:aa:aa:aa:aa  169.254.248.216/16
```

I personally find this output table MUCH easier to read on Windows than _Get-NetIPAddress_.

## Lookup

The `ntk lookup x` subcommand takes in an IP Address (such as _8.8.8.8_) and returns the hostname of the provided IP address. The reverse can be performed (hostname -> IP Address) by specifying `--name-lookup` (e.g. `ntk l -n dns.google.com`). Multiple IPv4 and IPv6 addresses may be returned when using `--name-lookup` (e.g. dns.google.com).

`ntk lookup -h`
```
Lookup the DNS name for a provided IP (or vice-versa)

Usage: ntk lookup [OPTIONS] <IP>

Arguments:
  <IP>  The IPv4 address or hostname lookup

Options:
  -n, --name-lookup  Convert a DNS hostname back into an IP
  -h, --help         Print help
```

### Examples

Example 1:  
Basic IP Address to hostname:  
`ntk lookup 8.8.8.8`
```
dns.google
```

Example 2:
A reverse 'lookup' of hostname to IP Address:
`ntk l -n dns.google`
```
8.8.4.4
8.8.8.8
2001:4860:4860::8888
2001:4860:4860::8844
```


## Mac Vendor

The `ntk mac-vendor x` subcommand takes in either the first [three octets (OUI)](https://en.wikipedia.org/wiki/Organizationally_unique_identifier) of a MAC address or an entire MAC address and returns the 'vendor label' / 'vendor name' of that device. Only the first three octets are required (e.g. FF:FF:FF) as these identify the manufactorer of the device. Currently this subcommand uses a HTTPS GET at layer 7 to do a lookup of the provided MAC Address. Two different online databases will be tried before determining the MAC is unknown or unlisted in the database.

Important note: these online URLs will throttle you if you attempt to use `ntk mac-vendor` at a rapid rate (such as in a script). Insert sleep statements between executions of the subcommand to prevent this.

`ntk mac-vendor -h`
```
Performs a HTTP 'Fetch' (GET) to determine the vendor of a provided MAC Address (e.g. FF:FF:FF)

Usage: ntk mac-vendor [OPTIONS] <ADDRESS>

Arguments:
  <ADDRESS>  At least the first three octets of a MAC Address to identify (OUI)

Options:
  -i, --ignore-certs  Ignore certificate checking similar to curl -k (insecure) [aliases: -k]
  -h, --help          Print help
```

### Examples

Example:  
Looking up a common router vendor/manufactorer:  
`ntk m e4:bf:fa`
```
Vantiva USA LLC
```

The command `ntk mac-vendor e4:bf:fa:aa:aa:aa` would have the same output, but you should [use the built in inference!](#subcommand-inference). Notice the last three octets of the 'full MAC Address' are nonsense here: the subcommand only cares about the [OUI](https://en.wikipedia.org/wiki/Organizationally_unique_identifier) (which is the first three octets).

## Ping

The `ntk ping x` subcommand sends out one (or more) ICMP packet(s) (EchoRequest) to a remote IP in order to determine layer 3 connectivity to a device. Currently this command transmits all packets in a single batch instead of waiting for a response before sending subsequent pings (when `--count` is greater than 1). The machine that is 'pinged' should respond with a 'reply' that indicates the ping was received. The trasmitting machine will then print how long it took for the packet 'reply' to be received from the original sent time.

This subcommand can also trace each of the hops (i.e.: the route) to a target by tracking TTL (time to live) timeout replies from devices along the path to the target IP. Specify the `--trace` argument (e.g. `ntk p -t 8.8.8.8`) to send packets with TTLs that increment from 1 to _max_.

Each packet sent from this machine will be assigned a sequence number from 1 to _max_. The stdout of this subcommand lists the sequence number followed by the time it took for a response. Please note that this subcommand uses the standard notation for 'no response' which is the asterisk character '*' when a reply is not received.

`ntk ping -h`
```
Ping (or optionally trace) a provided IP using ICMP

Usage: ntk ping [OPTIONS] <IP>

Arguments:
  <IP>  The IPv4 address to ping

Options:
  -t, --trace                    Trace the ping route using TTL
  -c, --count <COUNT>            Adjusts how many packets are sent for a ping in one batch (does not apply to trace) [default: 1]
      --packet-ttl <PACKET_TTL>  How long the packets should live before expiring [default: 10]
      --timeout <TIMEOUT>        How long to wait (in seconds) for replies before exiting [default: 10]
  -h, --help                     Print help
```

### Examples

Example 1:  
Ping the router in my local subnet:  
`ntk ping 10.0.0.1`
```
1   10.0.0.1         2.88ms
```

Example 2 (WSL2 native):  
Trace the hops to google DNS:  
`ntk p --t 8.8.8.8`
```
1   10.0.0.1         4.55ms
2   10.27.13.195     5.47ms
3   68.85.152.81     5.47ms
4   69.139.192.221   5.49ms
5   68.86.211.113    5.48ms
6   68.85.159.161    7.49ms
7   69.241.64.98     10.40ms
8   142.251.249.121  10.39ms
9   142.250.224.245  10.38ms
10  8.8.8.8          10.37ms
```

**NOTE:** The response times will be more accurate if you compile with-libpcap (or with _npcap_ on Windows).

## Scan

The `ntk scan x` subcommand is used to initiate a port scan on layer 4 of a remote target IP for replies from the target about the status of individual ports. By default, this subcommand will initiate a TCP SYN probe scan against an individual IP and will only output 'open' replies for individual port numbers. Ports that reply 'RST' (reset) can be displayed if the `--reset` flag is provided.

Some machines respond better if you perform a 'full TCP handshake' (`--full-handshake`) at layer 4 instead of 'partially connecting' with probes. On Windows, this 'full TCP handshake' can be performed even if using the version of `ntk.exe` that was not compiled with _npcap_ (the Windows version without _npcap_ (**native**) cannot perform TCP probe scans, only handshakes).

By default, an internal list of the 1000 most used ports will be scanned by `ntk scan x`. You can override which ports you want to scan with the `--start-range` and `--end-range` arguments. To scan a single port: use the same `--start-range` and `--end-range`.

More experienced users are also able to perform 'ACK' (e.g. `ntk s -a x`) and 'FIN' probes (e.g. `ntk s --fin-probe x`) using this subcommand.

`ntk scan -h`
```
Reveal open ports on a provided IP by attempting connections to them

Usage: ntk scan [OPTIONS] <IP>

Arguments:
  <IP>  The IPv4 address to scan for open TCP sockets

Options:
  -l, --lookup-name                Lookup the matched port numbers via hash and output a common name if known
  -r, --reset                      Show the ports that responded as (RST) during a SYN probe (likely closed)
  -d, --delay <DELAY>              How long to wait (in milliseconds) in-between connection attempts [default: 10]
  -s, --start-range <START_RANGE>  An optional starting port number to scan all ports from this port number up (inclusive)
  -e, --end-range <END_RANGE>      An optional ending port number to scan all ports up to this port number (inclusive)
      --timeout <TIMEOUT>          How long to wait (in seconds) for replies before exiting (doesn't apply for full handshake test) [default: 10]
  -a, --ack-probe                  When true, replace the default SYN probe with ACK instead
      --fin-probe                  When true, replace the ACK probe packet with a FIN flag instead
  -f, --full-handshake             When true, replace the default SYN probe with a full TCP handshake per port
      --source-port <SOURCE_PORT>  When provided: use this port as the source for the SYN probe instead of a random one
  -h, --help                       Print help
```

### Examples

TODO

# Compiling

You shouldn't need to compile `ntk` yourself, [please see the previous section on downloading pre-built binaries](#downloading-pre-built-binaries).

Network ToolKit can be compiled on either Linux or Windows. Rust and its ecosystem of compilation tools (e.g. cargo) must be installed first. [Please follow the official Rust documentation to install if you wish to compile yourself](https://rust-lang.org/tools/install/). You will also need to [install git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) in order to clone this remote repository.

## Cross Compilation Checks

The `./ubuntu-cross-check.bash` script checks the `ntk` binary is cross-compile compatible against both GNU and musl Linux as well as Windows (GNU check). This helps to ensure execution on common operating systems such as Ubuntu, RHEL, Alpine, and Windows 11. Support for Mac OS is planned but untested currently (do to the difficulty in cross checking Mac toolchain requirements on Ubuntu).

## Compiling on Ubuntu

I use _bash_ to compile on Ubuntu. [Please ensure Rust is installed](#compiling). These instructions should also work on RHEL based (CentOS, Oracle Linux) operating systems as well if you substitute the package manager and package name for the appropriate ones.

To compile and use **native** sockets (without libpcap):
```bash
# Collect the remote repository
git clone https://github.com/t-ambur/ntk
cd ntk

# sudo will be prompted to set cap_net_raw+ep socket permissions
./release-build.bash
```

To compile with-libpcap:
```bash
# libpcap-dev must be installed to compile against
sudo apt update
sudo apt install libpcap-dev

# Collect the remote repository
git clone https://github.com/t-ambur/ntk
cd ntk

# sudo will be prompted to set cap_net_raw+ep socket permissions
./release-build.bash
```

The compiled binary will be located at `./target/release/ntk` and can be `cp` (copied) to the desired location with the file permissions you choose (`chmod` and/or `chown`).

## Compiling on Windows

I use _powershell_ to compile on Windows 11. [Please ensure Rust is installed](#compiling). Please use an **administrator** shell for _powershell_.

To compile and use **native** sockets (without libpcap) (**NOT recommended**):
```ps1
# Collect the remote repository
git clone https://github.com/t-ambur/ntk
cd ntk

# Build using the standard cargo command
cargo build -r
```

To compile with-libpcap (**recommended**):
```ps1
# Collect the remote repository
git clone https://github.com/t-ambur/ntk
cd ntk

# Build using the standard cargo command
# The build.rs file will automatically link the bundled Npcap libs
#   against ntk when the feature flag is provided on Windows
cargo build -r -F with-libpcap
```

The compiled binary will be located at `.\target\release\ntk.exe`. You will likely need to use an **administrator** _powershell_ shell to execute it:
```ps1
.\target\release\ntk.exe help
```

If nothing happens when you attempt to execute `ntk.exe` (e.g. no output), [please ensure you have npcap installed](#dependencies).


## Compiling on Other Operating Systems

Use [the instructions for compiling on Windows using cargo](#compiling-on-windows) as a template (substituting the shell required for that operating system). The Rust toolchain must be supported on the chosen operating system in order to build/compile from source. You will have to figure out the developer dependencies required to link against.

# Known Issues

Please see the **TODO.md** file for a tracker of all known bugs, issues, and planned features to `ntk`. If you encounter an issue that is not already in **TODO.md** please open an GitHub issue on this repository.
