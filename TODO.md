# TODO

This is a mental notebook of possible TODOs on this project.

## Possible Features
- Download OCI database to mac-vendor argument and then allow offline MAC vendor query
- Support other RESTful HTTP commands (consider naming of the command)
    - POST
    - PUT
    - PATCH
    - DELETE
- Ping -> wait for response -> ping again (similar to expected behavior)
- Set IP Addresses?
- Banner search/grab? e.g. ssh, http, telnet, ftp

## Bugfixes
- Traceroute/Ping to cloudflare DNS 1.1.1.1 times out on final hop
    - Warrants further investigation (EchoResponse from a different IP?)
    - Noticed a similar issue on 8.8.8.8 in more complicated network scenarios
- When downloading using `ntk fetch -d` the archives from the release page the filenames are incorrect
- DNS lookup command prints the discovered hostname twice when ran via analyze
- ARP discovery sometimes seems less than expected on Windows over WiFi interface
- Windows shows 'pcap error: timeout expired while reading from a live capture' during analyze scan
    - Still seems to complete fine- this may be leaking out of the subcommand into the analyze function
- Fetch not found should throw/panic an error instead of downloading a 'not found' to a text file

## General / Misc
- Unit tests maybe
- Release pipeline should add tag version to the archives
- Consider crates.io release
- Look into adding to package managers on Ubuntu, Alpine, etc.
- Fetch should show status message alongside code 

## Linux
- Retest on RHEL or CentOS or Oracle Linux
- Problem with glibc version being compiled too new for older OS such as OL9
    - musl works on GNU linux -> next release get rid of 'GNU native' for only 'musl native'
- Test on Alpine

## Windows
- MSI installer?
- Discover subcommand should show friendly names of interfaces alongside GUID identifiers
- Gateway subcommand should show friendly names of interfaces alongside GUID identifiers
- Look into adding to a package manager such as choco

## Mac
- Test on ARM / Apple Silicon
    - Ping and Scan subcommands have socket issues even with sudo
    - Gateway looks strange for default route
- Test on Intel
- README.md needs update
    - Extract to /usr/local/bin instead of /usr/bin (and use sudo)
    - execute: sudo xattr-dr com.apple.quarantine /usr/local/bin ntk
    - Use sudo for discover subcommand, haven't found a setcap equivalent
