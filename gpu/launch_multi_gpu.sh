#!/bin/bash
# launch_multi_gpu.sh — QSB multi-GPU search
#
# Usage:
#   ./launch_multi_gpu.sh pinning <params.bin> [easy]
#   ./launch_multi_gpu.sh digest <params.bin> [easy] [first_start first_end]

set -e
MODE=${1:?Usage: $0 pinning|digest ...}; shift
NUM_GPUS=$(nvidia-smi -L 2>/dev/null | wc -l)
echo "=== QSB Multi-GPU Search ($NUM_GPUS GPUs) ==="
mkdir -p results
trap 'echo "Stopping..."; kill $(jobs -p) 2>/dev/null; wait; exit' INT TERM

if [ "$MODE" = "pinning" ]; then
    PARAMS=${1:?Need pinning params.bin}; shift
    EASY=${1:-}
    SEQS_PER_GPU=50000
    echo "  Pinning: $SEQS_PER_GPU seqs/GPU × 2^32 lt/seq"
    for ((i=0; i<NUM_GPUS; i++)); do
        START=$((i * SEQS_PER_GPU))
        echo "  GPU $i: seq $START..$((START+SEQS_PER_GPU-1))"
        CUDA_VISIBLE_DEVICES=$i ./qsb_search pinning "$PARAMS" $START $SEQS_PER_GPU $EASY \
            > results/log_pin_gpu$i.txt 2>&1 &
    done
elif [ "$MODE" = "digest" ]; then
    PARAMS=${1:?Need params.bin}; shift
    EASY=
    if [ "${1:-}" = "easy" ]; then
        EASY=easy
        shift
    fi
    DIGEST_START=${1:-0}
    DIGEST_END=${2:-}
    N=$(python3 -c "import struct;f=open('$PARAMS','rb');print(struct.unpack('<I',f.read(4))[0])")
    T=$(python3 -c "import struct;f=open('$PARAMS','rb');f.read(4);print(struct.unpack('<I',f.read(4))[0])")
    MF=$((N-T+1))
    if [ -z "$DIGEST_END" ]; then
        DIGEST_END=$MF
    fi
    if [ "$DIGEST_START" -lt 0 ] || [ "$DIGEST_END" -gt "$MF" ] || [ "$DIGEST_START" -ge "$DIGEST_END" ]; then
        echo "  Invalid digest first-index range [$DIGEST_START,$DIGEST_END) for n=$N t=$T (max $MF)"
        exit 1
    fi
    RANGE=$((DIGEST_END-DIGEST_START))
    PG=$(((RANGE+NUM_GPUS-1)/NUM_GPUS))
    echo "  Digest: n=$N t=$T first=[$DIGEST_START,$DIGEST_END)"
    for ((i=0; i<NUM_GPUS; i++)); do
        S=$((DIGEST_START + i*PG)); E=$((DIGEST_START + (i+1)*PG)); [ $E -gt $DIGEST_END ] && E=$DIGEST_END; [ $S -ge $DIGEST_END ] && break
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
