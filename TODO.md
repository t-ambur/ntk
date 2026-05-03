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
- **Packet scans don't work on Windows**
    - (needs rewrite to use libpcap for sending?, no native socket access?)
- Traceroute/Ping to cloudflare DNS 1.1.1.1 times out on final hop
    - Warrants further investigation (EchoResponse from a different IP?)
- When downloading using `ntk fetch -d` the archives from the release page the filenames are incorrect

## General / Misc
- Unit tests maybe

## Linux
- Retest Ubuntu after Windows changes
- Test on RHEL-based
- Test on Alpine

## Windows
- Finish testing Windows 11 after all fixes
- Test on Windows Server 2019/2022

## Mac
- Test on ARM
- Test on Intel
