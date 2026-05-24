# Changelog

Each version change in `ntk` should be recorded here.

## v0.5.0

- Adds new 'view' subcommand similar to how tcpdump works
- Adds new 'out' subcommand for POST / PUT / PATCH / DELETE with JSON bodies
- New output messages when the 'banner' subcommand fails to connect to a TCP port
- The discover subcommand now checks first against friendly name on MacOS just like on Windows
- The interface subcommand GUIDs are always quoted by when output on Windows
- Removed newline formatting when printing friendly names of interfaces via the interface subcommand on non-windows hosts (e.g. MacOS)
- Resolved all compiler warnings on Windows

## v0.4.0

- Adds the `banner` subcommand to scrape a remote host for all available banners
- Stop scanning loopback interface on Mac and BSD variants (lo0)
- Add flag to DNS lookup trace hop IP addresses

## v0.3.2

- Set to default TTL for the ping subcommand to '64' hops
    - Fixes a bug with cloudflare DNS (1.1.1.1) not being pingable with default settings
- The fetch subcommand now appropriately outputs an error if the `--download` flag gets an unsuccessful response code
- The fetch subcommand now has the correct filename for files with the *CONTENT_DISPOSITION* header
    - This fixes the downloaded name of `ntk` archives from the Github releases page
- The fetch subcommand now shows the total Megabytes (MB (1024*1024 bytes)) downloaded at completion
- The fetch subcommand no longer shows byte chunks downloaded for files without a *CONTENT_LENGTH* header
- Fix a typo in the Mac unarchive instructions and verifed Intel x86 pcap archive works (using sudo for some commands)
- Bugfix trace so it continues to run after a single hop prints TTL exceeded (*)

## v0.3.1

- Windows bugfix for the analyze subcommand printing 'pcap error: timeout expired while reading from a live capture'
- Bugfix for DNS hostname printing twice in analyze subcommand

## v0.3.0

- Print friendly names on Windows for what was previously just GUID interface responses (discover and gateway subcommands)
- Quote GUID interface names on Windows to make them easier to copy+paste
- Remove the device path to GUIDs printed from the gateway and discover subcommands on windows
- The standard 'GET' fetch subcommand now shows the 'canonical_reason' that corresponds with the code
    - e.g. 200 - OK
- Support ARM via musl builds
    - Clarify that musl 'native' builds can run on GNU linux
    - Replace the 'which binary' table with a bulleted list that is more detailed
- Change the build environment for GNU linux with-libpcap to support older glibc versions
- Remove the pre-built binary combinations (i.e. native/libpcap + OS) that didn't make sense to archive
- Add version tag to the release archives
- Add the architecture to each release archive (i.e. x86 or arm64)

## v0.2.0

- Enables layer 4 scanning using the libpcap mode
    - i.e. Windows can now run the scans!
- Many bugfixes for the layer 4 scanning
- Breaks out the functionality to ARP request a single host into a new function in discover

## v0.1.0

- Initial release on Github
