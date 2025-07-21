#!/bin/bash

# Convert zkey to arkzkey using /tmp directory
# Usage: ./convert.sh <path_to_zkey_file>

set -e

# Check input
if [ $# -eq 0 ]; then
    echo "Usage: $0 <path_to_zkey_file>"
    exit 1
fi

ZKEY_FILE="$1"

if [ ! -f "$ZKEY_FILE" ]; then
    echo "Error: File '$ZKEY_FILE' does not exist"
    exit 1
fi

# Get absolute path before changing directories
ZKEY_ABSOLUTE_PATH=$(realpath "$ZKEY_FILE")

# Create temp directory in /tmp
TEMP_DIR="/tmp/ark-zkey-$$"
echo "Using temp directory: $TEMP_DIR"

# Cleanup function
cleanup() {
    echo "Cleaning up temp directory: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
}

# Setup cleanup trap
trap cleanup EXIT

# Create temp directory and clone ark-zkey
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"
git clone https://github.com/seemenkina/ark-zkey.git
cd ark-zkey
cargo build

# Convert
cargo run --bin arkzkey-util "$ZKEY_ABSOLUTE_PATH"

# Check if arkzkey file was created (tool creates it in same directory as input)
ARKZKEY_FILE="${ZKEY_ABSOLUTE_PATH%.zkey}.arkzkey"

if [ ! -f "$ARKZKEY_FILE" ]; then
    echo "Could not find generated .arkzkey file at $ARKZKEY_FILE"
    exit 1
fi