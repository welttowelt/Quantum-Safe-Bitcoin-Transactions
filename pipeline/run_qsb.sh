#!/bin/bash
# run_qsb.sh — Complete QSB pipeline on vast.ai
#
# Usage:
#   Step 1 (before funding): ./run_qsb.sh setup A120
#   Step 2 (after funding):  ./run_qsb.sh search <txid> <vout> <sats> <dest_pkh>
#   Step 3 (after search):   ./run_qsb.sh assemble <locktime> <r1_indices> <r2_indices> <txid> <vout> <sats> <dest_pkh>
#
# Example full run:
#   ./run_qsb.sh setup A120
#   # Fund the P2SH address shown, then:
#   ./run_qsb.sh search abc123...def 0 100000 0014abcd...1234
#   # Wait for search to complete, read results, then:
#   ./run_qsb.sh assemble 12345 "1,5,23,44,67,89,102,110,115" "3,12,28,55,71,88,99,105,118" abc123...def 0 100000 0014abcd...1234

set -e
cd "$(dirname "$0")"

# Install deps if needed
if ! command -v nvcc &>/dev/null || ! dpkg -l libssl-dev &>/dev/null 2>&1; then
    echo "Installing dependencies..."
    apt-get update -qq && apt-get install -y -qq libssl-dev build-essential
fi

# Build GPU code if needed
if [ ! -f gpu/qsb_search ]; then
    echo "Building GPU search..."
    cd gpu && make && cd ..
fi

CMD=${1:?Usage: $0 setup|search|assemble ...}

case "$CMD" in
    setup)
        CONFIG=${2:-A120}
        echo "=== QSB Setup (config=$CONFIG) ==="
        python3 qsb_pipeline.py setup --config "$CONFIG"
        echo ""
        echo "Next: fund the P2SH output, then run:"
        echo "  ./run_qsb.sh search <funding_txid> <vout> <value_sats> <dest_pubkeyhash_hex>"
        ;;
    
    search)
        TXID=${2:?Need funding txid}
        VOUT=${3:?Need funding vout}
        VALUE=${4:?Need funding value in sats}
        DEST=${5:?Need destination pubkey hash (hex)}
        
        echo "=== QSB Export ==="
        python3 qsb_pipeline.py export \
            --funding-txid "$TXID" --funding-vout "$VOUT" \
            --funding-value "$VALUE" --dest-address "$DEST"
        
        NUM_GPUS=$(nvidia-smi -L 2>/dev/null | wc -l)
        echo ""
        echo "=== QSB Pinning Search ($NUM_GPUS GPUs) ==="
        cd gpu
        ./launch_multi_gpu.sh pinning ../pinning.bin
        
        echo ""
        echo "=== Pinning found! Now searching digest round 1... ==="
        ./launch_multi_gpu.sh digest ../digest_r1.bin
        
        echo ""
        echo "=== Round 1 found! Now searching digest round 2... ==="
        ./launch_multi_gpu.sh digest ../digest_r2.bin
        
        echo ""
        echo "=== All searches complete! ==="
        echo "Results in gpu/results/"
        ls -la results/
        cd ..
        
        echo ""
        echo "Next: read the results and run:"
        echo "  ./run_qsb.sh assemble <locktime> <r1_indices> <r2_indices> $TXID $VOUT $VALUE $DEST"
        ;;
    
    assemble)
        LT=${2:?Need locktime}
        R1=${3:?Need round1 indices (comma-separated)}
        R2=${4:?Need round2 indices (comma-separated)}
        TXID=${5:?Need funding txid}
        VOUT=${6:?Need funding vout}
        VALUE=${7:?Need funding value}
        DEST=${8:?Need destination pubkey hash}
        
        echo "=== QSB Assemble ==="
        python3 qsb_pipeline.py assemble \
            --locktime "$LT" --round1 "$R1" --round2 "$R2" \
            --funding-txid "$TXID" --funding-vout "$VOUT" \
            --funding-value "$VALUE" --dest-address "$DEST"
        
        echo ""
        echo "=== Raw transaction ==="
        cat qsb_raw_tx.hex
        echo ""
        echo ""
        echo "Broadcast via: https://mempool.space/tx/push"
        ;;
    
    *)
        echo "Usage: $0 setup|search|assemble ..."
        exit 1
        ;;
esac
