#!/bin/bash

set -eu

FEATURES=${1:+--features $1}

cargo build $FEATURES
./ubuntu-cross-check.bash
./setcap.bash
./target/debug/ntk help
