#!/bin/bash

set -e  

echo "Running cargo xtask build..."
cargo xtask build

echo "Running cargo build..."
cargo build

echo "Running RUST_LOG=info cargo xtask run..."
RUST_LOG=info cargo xtask run 
