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
- Ping out of a specific interface
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
- Look into adding to package managers: apt, dnf/yum, Alpine, brew, choco, snap, etc.
- Consider crates.io release

## Linux
- Retest both builds on RHEL or CentOS or Oracle Linux 8+
- Restest both builds on Ubuntu
- Test on Alpine

## Windows
- MSI installer?

## Mac
- Bugfix then retest on ARM / Apple Silicon
    - Ping and Scan subcommands have socket issues even with sudo
    - Gateway looks strange for default route
- Test on Intel
