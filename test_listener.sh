#!/bin/bash

# Quick test script for Suricata listener

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTENER_LOG="/tmp/suricata_listener-$(id -u).log"

echo "=== Suricata Listener Test ==="
echo ""
echo "1. Checking Suricata configuration..."
cd "$SCRIPT_DIR"
./configure_suricata.sh --show
echo ""

echo "2. Starting Python listener (Ctrl+C to stop)..."
echo "   The listener will detect T-Pot, create the socket, and restart Suricata."
echo "   Log file: $LISTENER_LOG"
echo ""

python3 "$SCRIPT_DIR/suricata_listener.py"

echo ""
echo "=== Test Complete ==="
echo "Check logs:"
echo "  tail -f $LISTENER_LOG"
