#!/bin/bash
# NOTE: For Secure Enclave access, you need to use build-macos-dev.sh instead!
#
# This script only signs the raw binary, but Secure Enclave requires:
# 1. A provisioning profile
# 2. Restricted entitlements (com.apple.application-identifier, com.apple.developer.team-identifier)
#
# The raw binary signing does NOT work for Secure Enclave because the
# restricted entitlements must be authorized by a provisioning profile,
# which can only be embedded in an app bundle.
#
# Please use: ./build-macos-dev.sh
#
# See the comments in build-macos-dev.sh for setup instructions.

echo "ERROR: For Secure Enclave access, use build-macos-dev.sh instead!"
echo ""
echo "Secure Enclave requires a provisioning profile embedded in an app bundle."
echo "The raw binary signing is insufficient."
echo ""
echo "Run: ./build-macos-dev.sh"
echo ""
exit 1
