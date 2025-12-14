#!/bin/bash
# Script to view all relevant logs including Rust, Android, and general Tauri logs
# Usage: ./view-all-logs.sh

echo "Viewing comprehensive logs for Secure Element Plugin..."
echo "This includes:"
echo "  - SecureKeysPlugin (Android)"
echo "  - Rust plugin logs"
echo "  - Tauri core logs"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Show logs from multiple sources
adb logcat | grep -E "(SecureKeysPlugin|tauri|RUST|JS)"
