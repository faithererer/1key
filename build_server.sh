#!/usr/bin/env bash
set -euo pipefail

# Paths
OUT_DIR="$(dirname "$0")"
OUT="$OUT_DIR/sso-ws-server-new"

# Build (strip debug info)
export GOOS=linux
export GOARCH=amd64
export GOAMD64=v3 
go build -o "$OUT"

echo "Built $OUT"
