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

## Bugfixes
- Traceroute/Ping to cloudflare DNS 1.1.1.1 times out on final hop
    - Warrants further investigation (EchoResponse from a different IP?)
- When downloading using `ntk fetch -d` the archives from the release page the filenames are incorrect
- DNS lookup command prints the discovered hostname twice when ran via analyze
- ARP discovery sometimes seems less than expected on Windows over WiFi interface
- Windows shows 'pcap error: timeout expired while reading from a live capture' during analyze scan
    - Still seems to complete fine- this may be leaking out of the subcommand into the analyze function

## General / Misc
- Unit tests maybe
- Release pipeline should add tag version to the archives
- Consider crates.io release
- Look into adding to package managers on Ubuntu, Alpine, etc.

## Linux
- Test on RHEL or CentOS or Oracle Linux
- Test on Alpine

## Windows
- Test on Windows Server 2019/2022
- MSI installer?
- Discover subcommand should show friendly names of interfaces alongside GUID identifiers
- Gateway subcommand should show friendly names of interfaces alongside GUID identifiers
- Look into adding to a package manager such as choco

## Mac
- Test on ARM
- Test on Intel
