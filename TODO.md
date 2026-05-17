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
- Ping out of a specific interface (i.e. ping -i eth0)
- Set IP Addresses?
- Banner search/grab? e.g. ssh, http, telnet, ftp
- Lookup hostname for traceroute hops
- Command similar to tcpdump
- Further optimize the response times of `ntk ping -t x.x.x.x`

## Linux
- Retest both builds on RHEL or CentOS or Oracle Linux 8+
- Restest both builds on Ubuntu
- Test on Alpine

## Windows
- MSI installer?
- ARP discovery sometimes seems less than expected on Windows over WiFi interface

## General / Misc
- Unit tests maybe
- Look into adding to package managers: apt, dnf/yum, Alpine, brew, choco, snap, etc.
- Consider crates.io release
