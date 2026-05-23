# TODO

This is a mental notebook of possible TODOs on this project.

## Possible Features
- Download OCI database to mac-vendor argument and then allow offline MAC vendor query
- Ping -> wait for response -> ping again (similar to expected behavior)
- Further optimize the response times of `ntk ping -t x.x.x.x` (trace)
- Further handling of friendly_name for both Mac and Windows

## Linux
- Test on Alpine

## Windows
- MSI installer (Include npcap?)
- ARP discovery sometimes seems less than expected on Windows over WiFi interface
- Resolve remaining unused warnings in compiler (no feature build)
- GUID should be quoted in place like the 'i' command for easy copy+paste

## General / Misc
- Unit tests maybe
- Look into adding to package managers: apt, dnf/yum, Alpine, brew, choco, snap, etc.
- Consider crates.io release
- Consider making trace a standalone subcommand
- Refactor interface lookup to use new map struct in all places
- Fix import warnings
