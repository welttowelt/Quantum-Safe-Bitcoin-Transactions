#!/bin/bash
# launch_multi_gpu.sh — QSB multi-GPU search
#
# Usage:
#   ./launch_multi_gpu.sh pinning [easy]             # Fake data, validates DER probability
#   ./launch_multi_gpu.sh digest <params.bin> [easy]  # Real params

set -e
MODE=${1:?Usage: $0 pinning|digest ...}; shift
NUM_GPUS=$(nvidia-smi -L 2>/dev/null | wc -l)
echo "=== QSB Multi-GPU Search ($NUM_GPUS GPUs) ==="
mkdir -p results
trap 'echo "Stopping..."; kill $(jobs -p) 2>/dev/null; wait; exit' INT TERM

if [ "$MODE" = "pinning" ]; then
    EASY=${1:-}
    SEQS_PER_GPU=50000
    echo "  Pinning: $SEQS_PER_GPU seqs/GPU × 2^32 lt/seq"
    for ((i=0; i<NUM_GPUS; i++)); do
        START=$((i * SEQS_PER_GPU))
        echo "  GPU $i: seq $START..$((START+SEQS_PER_GPU-1))"
        CUDA_VISIBLE_DEVICES=$i ./qsb_allgpu search $START $SEQS_PER_GPU $EASY \
            > results/log_pin_gpu$i.txt 2>&1 &
    done
elif [ "$MODE" = "digest" ]; then
    PARAMS=${1:?Need params.bin}; shift; EASY=${1:-}
    N=$(python3 -c "import struct;f=open('$PARAMS','rb');print(struct.unpack('<I',f.read(4))[0])")
    T=$(python3 -c "import struct;f=open('$PARAMS','rb');f.read(4);print(struct.unpack('<I',f.read(4))[0])")
    MF=$((N-T+1)); PG=$(((MF+NUM_GPUS-1)/NUM_GPUS))
    echo "  Digest: n=$N t=$T"
    for ((i=0; i<NUM_GPUS; i++)); do
        S=$((i*PG)); E=$(((i+1)*PG)); [ $E -gt $MF ] && E=$MF; [ $S -ge $MF ] && break
        echo "  GPU $i: first [$S,$E)"
        CUDA_VISIBLE_DEVICES=$i ./qsb_search digest "$PARAMS" $S $E $EASY \
            > results/log_dig_gpu$i.txt 2>&1 &
    done
fi

echo ""; echo "  Launched. Monitor: tail -f results/log_*_gpu0.txt"
while true; do
    for f in results/pinning_hit.txt results/digest_hit.txt; do
        [ -f "$f" ] && { echo ""; echo "=== HIT ==="; cat "$f"; kill $(jobs -p) 2>/dev/null; exit 0; }
    done
    sleep 30
    echo -n "  [$(date +%H:%M:%S)] "
    for ((i=0; i<NUM_GPUS; i++)); do
        R=$(grep -o '[0-9.]*M/s' results/log_*_gpu$i.txt 2>/dev/null | tail -1)
        echo -n "GPU$i:${R:-?} "
    done; echo ""
done
