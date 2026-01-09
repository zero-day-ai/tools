#!/bin/bash
# install.sh - Install Gibson Tools to system path
# This script copies built tools to /usr/local/bin

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BIN_DIR="bin"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

echo -e "${BLUE}Installing Gibson Tools to ${INSTALL_DIR}...${NC}"

if [ ! -d "$BIN_DIR" ]; then
    echo "Error: $BIN_DIR directory not found. Run build.sh first."
    exit 1
fi

# Count tools
count=0
for tool in "$BIN_DIR"/*; do
    if [ -f "$tool" ] && [ -x "$tool" ]; then
        tool_name=$(basename "$tool")
        cp "$tool" "$INSTALL_DIR/$tool_name"
        chmod +x "$INSTALL_DIR/$tool_name"
        ((++count)) || true
    fi
done

echo -e "${GREEN}Installed $count tools to ${INSTALL_DIR}${NC}"
