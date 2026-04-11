#!/bin/bash
# run_qsb.sh — Complete QSB pipeline on vast.ai
#
# Usage:
#   Step 1 (before funding): ./run_qsb.sh setup A120
#   Step 2 (after funding):  ./run_qsb.sh search <txid> <vout> <sats> <dest_pkh> [helper_txid helper_vout]
#   Step 3 (after search):   ./run_qsb.sh assemble <sequence> <locktime> <r1_indices> <r2_indices> <txid> <vout> <sats> <dest_pkh> [helper_txid helper_vout [helper_script_sig_hex]]
#
# Example full run:
#   ./run_qsb.sh setup A120
#   # Fund the QSB output shown, then:
#   ./run_qsb.sh search abc123...def 0 100000 0014abcd...1234 <helper_txid> <helper_vout>
#   # Wait for search to complete, read results, then:
#   ./run_qsb.sh assemble 4294967294 12345 "1,5,23,44,67,89,102,110,115" "3,12,28,55,71,88,99,105,118" abc123...def 0 100000 0014abcd...1234 <helper_txid> <helper_vout> [helper_script_sig_hex]

set -e
cd "$(dirname "$0")"
PLACEHOLDER_HELPER_TXID=0000000000000000000000000000000000000000000000000000000000000000

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
        echo "Next: fund the QSB output shown by setup, then run:"
        echo "  ./run_qsb.sh search <funding_txid> <vout> <value_sats> <dest_pubkeyhash_hex> [helper_txid helper_vout]"
        ;;
    
    search)
        TXID=${2:?Need funding txid}
        VOUT=${3:?Need funding vout}
        VALUE=${4:?Need funding value in sats}
        DEST=${5:?Need destination pubkey hash (hex)}
        HELPER_TXID=${6:-$PLACEHOLDER_HELPER_TXID}
        HELPER_VOUT=${7:-0}
        
        echo "=== QSB Export ==="
        python3 qsb_pipeline.py export \
            --helper-txid "$HELPER_TXID" --helper-vout "$HELPER_VOUT" \
            --funding-txid "$TXID" --funding-vout "$VOUT" \
            --funding-value "$VALUE" --dest-address "$DEST"
        
        NUM_GPUS=$(nvidia-smi -L 2>/dev/null | wc -l)
        echo ""
        echo "=== QSB Pinning Search ($NUM_GPUS GPUs) ==="
        cd gpu
        ./launch_multi_gpu.sh pinning ../pinning.bin

        PIN_RESULT=results/pinning_hit.txt
        if [ ! -f "$PIN_RESULT" ]; then
            echo "No pinning result found at $PIN_RESULT"
            exit 1
        fi
        SEQUENCE=$(grep '^sequence=' "$PIN_RESULT" | head -1 | cut -d= -f2)
        LOCKTIME=$(grep '^locktime=' "$PIN_RESULT" | head -1 | cut -d= -f2)
        if [ -z "$SEQUENCE" ] || [ -z "$LOCKTIME" ]; then
            echo "Could not parse sequence/locktime from $PIN_RESULT"
            cat "$PIN_RESULT"
            exit 1
        fi
        echo ""
        echo "=== Pinning found: sequence=$SEQUENCE locktime=$LOCKTIME ==="
        cd ../pipeline
        python3 qsb_pipeline.py export-digest \
            --sequence "$SEQUENCE" --locktime "$LOCKTIME" \
            --helper-txid "$HELPER_TXID" --helper-vout "$HELPER_VOUT" \
            --funding-txid "$TXID" --funding-vout "$VOUT" \
            --funding-value "$VALUE" --dest-address "$DEST"

        echo ""
        echo "=== Pinning found! Now searching digest round 1... ==="
        cd ../gpu
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
        echo "  ./run_qsb.sh assemble $SEQUENCE $LOCKTIME <r1_indices> <r2_indices> $TXID $VOUT $VALUE $DEST [helper_txid helper_vout [helper_script_sig_hex]]"
        ;;
    
    assemble)
        SEQ=${2:?Need sequence}
        LT=${3:?Need locktime}
        R1=${4:?Need round1 indices (comma-separated)}
        R2=${5:?Need round2 indices (comma-separated)}
        TXID=${6:?Need funding txid}
        VOUT=${7:?Need funding vout}
        VALUE=${8:?Need funding value}
        DEST=${9:?Need destination pubkey hash}
        HELPER_TXID=${10:-$PLACEHOLDER_HELPER_TXID}
        HELPER_VOUT=${11:-0}
        HELPER_SCRIPT_SIG_HEX=${12:-}
        
        echo "=== QSB Assemble ==="
        python3 qsb_pipeline.py assemble \
            --sequence "$SEQ" --locktime "$LT" --round1 "$R1" --round2 "$R2" \
            --helper-txid "$HELPER_TXID" --helper-vout "$HELPER_VOUT" \
            --helper-script-sig-hex "$HELPER_SCRIPT_SIG_HEX" \
            --funding-txid "$TXID" --funding-vout "$VOUT" \
            --funding-value "$VALUE" --dest-address "$DEST"
        
        echo ""
        echo "=== Raw transaction ==="
        cat qsb_raw_tx.hex
        echo ""
        echo ""
        echo "Broadcast via a miner-direct / private relay path (e.g. Slipstream), not the public mempool."
        ;;
    
    *)
        echo "Usage: $0 setup|search|assemble ..."
        exit 1
        ;;
esac
