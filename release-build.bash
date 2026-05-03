#!/bin/bash

set -eu

FEATURES=${1:+--features $1}

cargo build -r $FEATURES
./setcap.bash
ls -lah ./target/release/ntk
./target/release/ntk -h
