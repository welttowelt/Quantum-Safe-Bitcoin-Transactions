#!/bin/bash
# QSB GPU Setup for vast.ai
# Installs libsecp256k1 + OpenSSL, builds the C search program
set -e

echo "=== QSB GPU Setup ==="

# Install dependencies
echo "[1/4] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq libsecp256k1-dev libssl-dev build-essential python3-pip > /dev/null 2>&1
pip install coincurve --break-system-packages 2>/dev/null || pip install coincurve 2>/dev/null
echo "  Done"

# Check OpenMP / thread count
echo "[2/4] System info..."
echo "  CPUs: $(nproc)"
echo "  RAM: $(free -h | awk '/^Mem:/{print $2}')"
if command -v nvidia-smi &> /dev/null; then
    echo "  GPU: $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo 'none')"
fi

# Build
echo "[3/4] Building C search program..."
cd "$(dirname "$0")"
make clean && make
echo "  Built: $(ls -la qsb_search | awk '{print $5, $9}')"

# Quick test
echo "[4/4] Quick benchmark..."
./qsb_search bench

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Benchmark:  ./qsb_search bench"
echo "  2. Pin search:  python3 run_search.py pin --diff 16 --count 100000"
echo "  3. Full search: python3 run_search.py full --diff 16"
echo "  4. Real search: python3 run_search.py full --diff 0 --count 10000000"
