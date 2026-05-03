#!/bin/bash

sudo setcap cap_net_raw+ep ./target/debug/ntk || true
sudo setcap cap_net_raw+ep ./target/release/ntk || true
