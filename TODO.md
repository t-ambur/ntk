# TODO

This is a mental notebook of possible TODOs on this project.

## Possible Features
- Download OCI database to mac-vendor argument and then allow offline MAC vendor query
- Ping -> wait for response -> ping again (similar to expected behavior)
- Further optimize the response times of `ntk ping -t x.x.x.x` (trace)
    - Make trace a standalone subcommand during this optimization `ntk trace x.x.x.x`
- Implement filtering for view subcommand
    - Especially for active SSH connections spamming native socket mode on Ubuntu
- Implement non-JSON (plaintext) support for out subcommand
- Implement providing the JSON in the CLI itself instead of needing a file for the out subcommand
- Add banner search to the analyze command

## Linux
- Test on Alpine

## Windows
- MSI installer (Include npcap?)
- ARP discovery sometimes seems less than expected on Windows over WiFi interface

## Mac
- Consider cleaning up / filtering interface subcommand output (there is a lot here on this operating system)

## General / Misc
- Unit tests maybe
- Look into adding to package managers: apt, dnf/yum, Alpine, brew, choco, snap, etc.
- Consider crates.io release
