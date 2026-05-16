# Changelog

Each version change in `ntk` should be recorded here.

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
- Remove the build combinations (i.e. native/libpcap + OS) that didn't make sense to run
- Add version tag to the release archives
- Add the architecture to each release archive (i.e. x86 or arm64)

## v0.2.0

- Enables layer 4 scanning using the libpcap mode
    - i.e. Windows can now run the scans!
- Many bugfixes for the layer 4 scanning
- Breaks out the functionality to ARP request a single host into a new function in discover

## v0.1.0

- Initial release on Github
