#!/bin/bash

# ============================================================
# TruePix Benchmark Script
# 8 组命令 × 10 次正式运行 + 1 次预热
# ============================================================

RUNS=10
WARMUP=1
SLEEP_BETWEEN=5
OUTDIR="benchmark_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTDIR"

echo "============================================================"
echo "TruePix Benchmark"
echo "Output dir: $OUTDIR"
echo "Runs per case: $RUNS"
echo "Warmup per case: $WARMUP"
echo "============================================================"

# 定义 8 组测试
# 格式: "标签|命令参数"
CASES=(
    "A1_gray_nozk|--input input.mp4 --operation gray --no-zk"
    "A2_gray_zk|--input input.mp4 --operation gray --zk"
    "B1_invert_nozk|--input input.mp4 --operation invert --no-zk"
    "B2_invert_zk|--input input.mp4 --operation invert --zk"
    "C1_mask_nozk|--input input.mp4 --operation mask --no-zk"
    "C2_mask_zk|--input input.mp4 --operation mask --zk"
    "D1_crop_nozk|--input input.mp4 --operation crop --crop 0.2 0.8 0.2 0.8 --no-zk"
    "D2_crop_zk|--input input.mp4 --operation crop --crop 0.2 0.8 0.2 0.8 --zk"
)

cleanup_before_run() {
    rm -f vole_ext_prover_*.json
    rm -f vole_ext_verifier_*.json
    rm -f input.txt output.txt output.mp4

    # 可选：清缓存，需要 sudo
    # sync
    # echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
}

run_one() {
    local tag="$1"
    local args="$2"
    local logfile="$3"

    cleanup_before_run

    local start
    local end
    start=$(date +%s.%N)

    ./TruePix.sh $args > "$logfile" 2>&1
    local exit_code=$?

    end=$(date +%s.%N)
    local wall
    wall=$(echo "$end - $start" | bc)

    echo "exit_code=$exit_code" > "${logfile%.log}.meta"
    echo "wall_time=$wall" >> "${logfile%.log}.meta"

    echo "  -> $tag done, exit=$exit_code, wall=${wall}s"
}

for case_def in "${CASES[@]}"; do
    TAG="${case_def%%|*}"
    ARGS="${case_def#*|}"
    CASE_DIR="$OUTDIR/$TAG"
    mkdir -p "$CASE_DIR"

    echo ""
    echo "============================================================"
    echo "Case: $TAG"
    echo "Args: $ARGS"
    echo "============================================================"

    # 预热
    for w in $(seq 1 $WARMUP); do
        echo "[$TAG] Warmup $w / $WARMUP"
        run_one "$TAG" "$ARGS" "$CASE_DIR/warmup_${w}.log"
        sleep $SLEEP_BETWEEN
    done

    # 正式运行
    for i in $(seq 1 $RUNS); do
        echo "[$TAG] Run $i / $RUNS"
        run_one "$TAG" "$ARGS" "$CASE_DIR/run_${i}.log"
        sleep $SLEEP_BETWEEN
    done
done

echo ""
echo "============================================================"
echo "All runs completed."
echo "Logs saved to: $OUTDIR"
echo "============================================================"
