#!/bin/bash
# run_pinning.sh — Sharded pinning search using qsb_search
#
# Usage:
#   Machine 1: ./run_pinning.sh 0
#   Machine 2: ./run_pinning.sh 1
#   Machine 3: ./run_pinning.sh 2
#   etc.
#
# Each machine searches NUM_GPUS × 50,000 sequences
# Expected hit after ~21,600 total sequences across all machines

set -e
cd "$(dirname "$0")"

MACHINE_ID=${1:?Usage: $0 <machine_id> (0,1,2,...)}
SEQS_PER_GPU=50000
NUM_GPUS=$(nvidia-smi -L 2>/dev/null | wc -l)
OFFSET=$((MACHINE_ID * NUM_GPUS * SEQS_PER_GPU))

echo "=== QSB Pinning Search ==="
echo "  Machine: $MACHINE_ID ($NUM_GPUS GPUs)"
echo "  Sequence range: $OFFSET .. $((OFFSET + NUM_GPUS * SEQS_PER_GPU - 1))"

# Build if needed
if [ ! -f qsb_search ]; then
    echo "  Building..."
    apt-get install -y -qq libssl-dev 2>/dev/null
    make
fi

if [ ! -f ../pinning.bin ]; then
    echo "  ERROR: ../pinning.bin not found. Run pipeline export first."
    exit 1
fi

# Launch all GPUs
mkdir -p results
trap 'echo "Stopping..."; kill $(jobs -p) 2>/dev/null; wait; exit' INT TERM

for ((i=0; i<NUM_GPUS; i++)); do
    START=$((OFFSET + i * SEQS_PER_GPU))
    echo "  GPU $i: seq $START..$((START + SEQS_PER_GPU - 1))"
    CUDA_VISIBLE_DEVICES=$i stdbuf -oL ./qsb_search pinning ../pinning.bin $START $SEQS_PER_GPU \
        > results/log_m${MACHINE_ID}_gpu$i.txt 2>&1 &
done

echo ""
echo "  All GPUs launched. Monitoring..."

# Monitor
while true; do
    if [ -f results/pinning_hit.txt ]; then
        echo ""
        echo "========================================="
        echo "  HIT FOUND!"
        cat results/pinning_hit.txt
        echo "========================================="
        kill $(jobs -p) 2>/dev/null
        exit 0
    fi
    sleep 30
    echo -n "  [$(date +%H:%M:%S)] "
    for ((i=0; i<NUM_GPUS; i++)); do
        R=$(grep -o '[0-9.]*M/s' results/log_m${MACHINE_ID}_gpu$i.txt 2>/dev/null | tail -1)
        echo -n "GPU$i:${R:-wait} "
    done
    echo ""
done
