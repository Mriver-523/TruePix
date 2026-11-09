#!/bin/bash
#
# Copyright 2017 Riad S. Wahby and the Hyrax authors
# Copyright 2025-2026 the TruePix authors
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
#
# TruePix Video Editing and Proof Generation Script
# Optimized version with function encapsulation to reduce process overhead

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUEPIX_ROOT="$SCRIPT_DIR"
VIDEO_EDITION_DIR="$(dirname "$SCRIPT_DIR")/VideoEdition"
PWS_DIR="$TRUEPIX_ROOT/pws"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
# The pypws / pymiracl cffi packages live in sibling trees; without these
# entries `import pypws` fails in every python3 invocation below.
export PYTHONPATH="$REPO_ROOT/libpws/python:$REPO_ROOT/pymiracl/python${PYTHONPATH:+:$PYTHONPATH}"

echo "Starting TruePix processing..."
echo "TruePix root: $TRUEPIX_ROOT"
echo "Video edition dir: $VIDEO_EDITION_DIR"
echo "PWS directory: $PWS_DIR"

# Fresh clones do not include compiled Hyrax .so files.
if [ ! -e "$REPO_ROOT/libpws/python/pypws/lib/pylibpws.so" ]; then
    echo "Error: missing pylibpws.so (libpws not built)."
    echo "From the repository root run:  ./setup.sh"
    exit 1
fi
if [ ! -e "$REPO_ROOT/pymiracl/python/pymiracl/lib/pymiracl.so" ]; then
    echo "Error: missing pymiracl.so (pymiracl not built)."
    echo "From the repository root run:  ./setup.sh"
    exit 1
fi
if [ ! -x "$TRUEPIX_ROOT/fft_gkr" ]; then
    echo "Error: missing executable TruePix-main/fft_gkr."
    echo "From the repository root run:  ./setup.sh"
    exit 1
fi

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --input <video_file>      Input video file path (required for non-random mode)"
    echo "  --output <video_file>     Output video file path (default: output.mp4)"
    echo "  --operation <op>          Editing operation: gray, invert, mask, crop"
    echo "  --constraint <size>       Constraint size for TruePix proofs (default: auto-calculated)"
    echo "  --crop <x1> <x2> <y1> <y2> Crop window 0-1 (video crop, or random crop keep-mask;"
    echo "                            default for --random crop: 0.2 0.8 0.2 0.8)"
    echo "  --mb-width <W>            Macroblock grid width for random crop (H=C/W); default: auto"
    echo "  --random                  Use random input for testing (skip video editing)"
    echo "  --frames <N>              Total runs (with --threads). Video mode edits once and"
    echo "                            every worker proves the same input.txt/output.txt."
    echo "  --threads <T>             Worker processes, one physical core each"
    echo "                            Each thread runs n=frames/threads times"
    echo "  Multi-thread environment knobs (launcher only):"
    echo "    TRUEPIX_WARMUP=K          K extra leading rounds per thread, excluded from sums (default 1)"
    echo "    TRUEPIX_PROVE_SLOTS=K     max concurrent proves (default 4)"
    echo "    TRUEPIX_VERIFY_BARRIER=0  let verify overlap other workers' proves (default 1 = barrier)"
    echo "    TRUEPIX_CPU_POLICY=pack   fill the fastest L3 domain first (default spread)"
    echo "    TRUEPIX_WORKER_CPUS=0-3   explicit worker CPU list"
    echo "    TRUEPIX_MPS=0             do not start a per-user CUDA MPS daemon for --gpu with T>1"
    echo "  --zk                      Enable full ZK (GKR product-mask + Orion mask/masked; default)"
    echo "  --no-zk                   Disable ZK (plain GKR VOLE + Orion single polynomial)"
    echo "  --gpu                     Use GPU-optimized GKR (libnative_fp2_gpu.so) if a device exists (default)"
    echo "  --no-gpu                  Force the CPU GKR path (same as TruePix_new_test_3s)"
    echo "  --help                    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --input input.mp4 --operation gray --zk"
    echo "  $0 --input input.mp4 --operation crop --crop 0.2 0.8 0.2 0.8"
    echo "  $0 --random --operation gray --constraint 1350"
    echo "  $0 --random --operation gray --constraint 1350 --no-gpu"
    echo "  $0 --random --operation gray --constraint 1350 --gpu"
    echo "  $0 --random --operation gray --constraint 1350 --frames 8 --threads 4"
    echo "  $0 --input input.mp4 --operation gray --constraint 1350 --frames 8 --threads 4"
}

get_pws_file() {
    local operation=$1
    case $operation in
        "gray") echo "gray.pws" ;;
        "invert"|"inv") echo "inv.pws" ;;
        "mask") echo "mask.pws" ;;
        "crop") echo "Crop.pws" ;;
        *) echo "unknown.pws" ;;
    esac
}

get_pws_path() {
    local operation=$1
    local pws_file
    pws_file=$(get_pws_file "$operation")
    echo "pws/$pws_file"
}

calculate_constraint_size() {
    local input_file="$1"
    if [ -f "$input_file" ]; then
        wc -l < "$input_file"
    else
        echo "1350"
    fi
}

python_signer() {
    # $1: constraint_size, $2: use_zk, $3: pws_file
    echo "=== Running TruePix Signer ==="
    python3 run_truepix_signer.py -c "$1" -z "$2" --pws "$3"
}

python_prover() {
    # $1: pws_file, $2: constraint_size, $3: z_flag
    echo "=== Running TruePix Prover ==="
    local prover_args=(-p "$1" -c="$2" -z "$3" -o "hyraxproof" -i "input.txt")
    python3 run_truepix_prover.py "${prover_args[@]}"
}

python_verifier() {
    # $1: pws_file, $2: constraint_size, $3: z_flag
    echo "=== Running TruePix Verifier ==="
    local verifier_args=(-p "$1" -c="$2" -z "$3" -v "hyraxproof" -i "input.txt")
    python3 run_truepix_verifier.py "${verifier_args[@]}"
}

run_truepix_proofs_optimized() {
    local operation=$1
    local use_random=$2
    local use_zk=$3
    local pws_file=$4
    local constraint_size=$5

    echo "Running optimized TruePix proof processes..."
    echo "Operation: $operation, Random: $use_random, ZK: $use_zk, PWS: $pws_file, Constraint: $constraint_size"

    # --zk = GKR product-mask (circuitnizkvec_vole_ZK) + Orion_zk
    # --no-zk = plain GKR (circuitnizkvec_vole) + Orion_nonzk
    local z_flag
    if [ "$use_zk" = "1" ]; then
        z_flag="1"
    else
        z_flag="2"
    fi

    if [ "$use_random" = "1" ]; then
        echo "=== Preparing shared random input/output ==="
        # Keep the caller's PYTHONPATH. PYTHONPATH=. would drop the
        # libpws/python and pymiracl/python entries exported above.
        if ! PYTHONPATH="$TRUEPIX_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
            TRUEPIX_CROP_REGION="${CROP_COORDS:-}" \
            TRUEPIX_MB_WIDTH="${MB_WIDTH:-}" \
            python3 - <<PY
from libTruePix.defs import Defs
from libTruePix.fp2_link import prepare_random_circuit_io
import os
Defs.configure()
kwargs = {}
crop = os.environ.get("TRUEPIX_CROP_REGION", "").strip()
mb_w = os.environ.get("TRUEPIX_MB_WIDTH", "").strip()
if crop:
    parts = crop.split()
    if len(parts) != 4:
        raise SystemExit("TRUEPIX_CROP_REGION must be: x1 x2 y1 y2")
    kwargs["crop_region"] = tuple(float(x) for x in parts)
if mb_w:
    kwargs["mb_width"] = int(mb_w)
info = prepare_random_circuit_io("$pws_file", int("$constraint_size"), **kwargs)
print("Prepared random IO:", info)
PY
        then
            echo "Error: failed to prepare shared random input/output"
            return 1
        fi
    fi

    if ! python_signer "$constraint_size" "$use_zk" "$pws_file"; then
        echo "Error: TruePix Signer failed"
        return 1
    fi

    if ! python_prover "$pws_file" "$constraint_size" "$z_flag"; then
        echo "Error: TruePix Prover failed"
        return 1
    fi

    if ! python_verifier "$pws_file" "$constraint_size" "$z_flag"; then
        echo "Error: TruePix Verifier failed"
        return 1
    fi

    echo "All TruePix proof processes completed successfully"
    return 0
}

link_worker_bins() {
    local dir=$1
    mkdir -p "$dir"
    local name
    for name in fft_gkr \
        linearPC_multi_commit linearPC_multi_prove linearPC_multi_open \
        linearPC_multi_commit_zk linearPC_multi_prove_zk linearPC_multi_open_zk
    do
        if [ -e "$TRUEPIX_ROOT/$name" ]; then
            ln -sfn "$TRUEPIX_ROOT/$name" "$dir/$name"
        fi
    done
}


sum_metric() {
    # $1 log file, $2 metric label. Prints "sum count".
    # Samples before a TRUEPIX_MEASURE_BEGIN line (warm-up rounds) are dropped.
    awk -F: -v label="$2" '
        /^TRUEPIX_MEASURE_BEGIN/ { sum = 0; n = 0; next }
        index($1, label) == 1 {
            gsub(/seconds/, "", $2)
            sum += $2
            n++
        }
        END { printf "%.6f %d\n", sum + 0, n + 0 }
    ' "$1"
}


link_worker_io() {
    # Prefer a hard link so workers share one page-cache copy of the
    # read-only witness; fall back to a symlink, then a copy.
    local src="$1"
    local dst="$2"
    if ln -f "$src" "$dst" 2>/dev/null; then
        return 0
    fi
    if ln -sfn "$src" "$dst" 2>/dev/null; then
        return 0
    fi
    cp -f "$src" "$dst"
}

# Expand a sysfs CPU list such as "0,16" or "0-7,16-23", one id per line.
expand_cpu_list() {
    local spec="$1" part start end i
    spec="${spec//,/ }"
    for part in $spec; do
        if [[ "$part" == *-* ]]; then
            start="${part%-*}"
            end="${part#*-}"
            for ((i = start; i <= end; i++)); do
                echo "$i"
            done
        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            echo "$part"
        fi
    done
}

# Shared CPU list of the last-level cache (L3 when present).
llc_shared_list() {
    local cpu="$1" dir idx level shared best_level=-1 best=""
    dir="/sys/devices/system/cpu/cpu${cpu}/cache"
    if [ ! -d "$dir" ]; then
        echo "cpu${cpu}"
        return
    fi
    for idx in "$dir"/index*; do
        [ -d "$idx" ] || continue
        level="$(cat "$idx/level" 2>/dev/null || echo 0)"
        shared="$(cat "$idx/shared_cpu_list" 2>/dev/null || true)"
        [ -n "$shared" ] || continue
        if [ "$level" -eq 3 ]; then
            echo "$shared"
            return
        fi
        if [ "$level" -gt "$best_level" ]; then
            best_level="$level"
            best="$shared"
        fi
    done
    echo "${best:-cpu${cpu}}"
}

# Boost capability of one logical CPU (larger = faster core). Uses the
# AMD preferred-core ranking / CPPC highest_perf when exposed, else the max
# frequency, else 0 (all cores equal).
cpu_perf_rank() {
    local base="/sys/devices/system/cpu/cpu$1" f v
    for f in "$base/cpufreq/amd_pstate_prefcore_ranking" \
             "$base/acpi_cppc/highest_perf" \
             "$base/cpufreq/amd_pstate_highest_perf" \
             "$base/cpufreq/cpuinfo_max_freq"; do
        v="$(cat "$f" 2>/dev/null || true)"
        if [[ "$v" =~ ^[0-9]+$ ]]; then
            echo "$v"
            return
        fi
    done
    echo 0
}

# Print `need` logical CPU ids, one per line.
# TRUEPIX_WORKER_CPUS="0-3" or "0,2,4,6" pins workers to an explicit list.
# Otherwise physical cores are ranked by cpu_perf_rank inside each
# last-level cache, and TRUEPIX_CPU_POLICY picks the order:
#   spread (default) one core at a time, round-robin across caches
#   pack             fill the fastest cache's cores before the next cache
# SMT siblings are used only after every physical core is taken.
# The list repeats if more workers are requested than logical CPUs.
select_worker_cpus() {
    local need="$1"
    local -a online=()
    local cpu path siblings min sib llc
    local -A core_primary=()
    local -A core_smt=()
    local -A core_llc=()
    local old_nullglob

    if [ -n "${TRUEPIX_WORKER_CPUS:-}" ]; then
        local -a fixed=()
        local k
        mapfile -t fixed < <(expand_cpu_list "$TRUEPIX_WORKER_CPUS")
        if [ "${#fixed[@]}" -gt 0 ]; then
            for ((k = 0; k < need; k++)); do
                echo "${fixed[$((k % ${#fixed[@]}))]}"
            done
            return
        fi
    fi

    old_nullglob="$(shopt -p nullglob || true)"
    shopt -s nullglob
    for path in /sys/devices/system/cpu/cpu[0-9]*; do
        cpu="${path##*/cpu}"
        [[ "$cpu" =~ ^[0-9]+$ ]] || continue
        if [ -f "$path/online" ] && [ "$(cat "$path/online" 2>/dev/null)" != "1" ]; then
            continue
        fi
        online+=("$cpu")
    done
    eval "$old_nullglob"

    if [ "${#online[@]}" -eq 0 ]; then
        local nproc_n i
        nproc_n="$(nproc 2>/dev/null || echo 1)"
        for ((i = 0; i < need; i++)); do
            echo $((i % nproc_n))
        done
        return
    fi

    for cpu in "${online[@]}"; do
        siblings="$(cat "/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list" 2>/dev/null || echo "$cpu")"
        min=""
        while IFS= read -r sib; do
            if [ -z "$min" ] || [ "$sib" -lt "$min" ]; then
                min="$sib"
            fi
        done < <(expand_cpu_list "$siblings")
        [ -n "$min" ] || min="$cpu"
        if [ -z "${core_primary[$min]+x}" ] || [ "$cpu" -lt "${core_primary[$min]}" ]; then
            core_primary["$min"]="$cpu"
        fi
        if [ "$cpu" != "$min" ]; then
            core_smt["$min"]+="$cpu "
        fi
    done

    local -a primaries=()
    while IFS= read -r min; do
        [ -n "$min" ] || continue
        primaries+=("$min")
        core_llc["$min"]="$(llc_shared_list "${core_primary[$min]}")"
    done < <(
        for min in "${!core_primary[@]}"; do
            printf '%s %s\n' "$(cpu_perf_rank "${core_primary[$min]}")" "$min"
        done | sort -k1,1nr -k2,2n | awk '{print $2}'
    )

    local -A llc_seen=()
    local -a llc_order=()
    local -A llc_cores=()
    for min in "${primaries[@]}"; do
        llc="${core_llc[$min]}"
        if [ -z "${llc_seen[$llc]+x}" ]; then
            llc_seen["$llc"]=1
            llc_order+=("$llc")
        fi
        llc_cores["$llc"]+="$min "
    done

    local -a llc_smt=()
    local d cores_line max_smt s c
    local -a cores sibs
    for llc in "${llc_order[@]}"; do
        read -r -a cores <<< "${llc_cores[$llc]}"
        max_smt=0
        for c in "${cores[@]}"; do
            sibs=()
            if [ -n "${core_smt[$c]:-}" ]; then
                mapfile -t sibs < <(printf '%s\n' ${core_smt[$c]} | sort -n)
            fi
            if [ "${#sibs[@]}" -gt "$max_smt" ]; then
                max_smt="${#sibs[@]}"
            fi
        done
        local seq=""
        for ((s = 0; s < max_smt; s++)); do
            for c in "${cores[@]}"; do
                sibs=()
                if [ -n "${core_smt[$c]:-}" ]; then
                    mapfile -t sibs < <(printf '%s\n' ${core_smt[$c]} | sort -n)
                fi
                if [ "$s" -lt "${#sibs[@]}" ]; then
                    seq+="${sibs[$s]} "
                fi
            done
        done
        llc_smt+=("$seq")
    done

    local -a ordered=()
    local -a ptr=()
    local progressed got
    for d in "${!llc_order[@]}"; do
        ptr[$d]=0
    done
    progressed=1
    got=0
    if [ "${TRUEPIX_CPU_POLICY:-spread}" = "pack" ]; then
        for d in "${!llc_order[@]}"; do
            read -r -a cores <<< "${llc_cores[${llc_order[$d]}]}"
            ordered+=("${cores[@]}")
        done
        progressed=0
    fi
    while [ "$progressed" -eq 1 ]; do
        progressed=0
        for d in "${!llc_order[@]}"; do
            read -r -a cores <<< "${llc_cores[${llc_order[$d]}]}"
            if [ "${ptr[$d]}" -lt "${#cores[@]}" ]; then
                ordered+=("${cores[${ptr[$d]}]}")
                ptr[$d]=$((ptr[$d] + 1))
                progressed=1
                got=$((got + 1))
            fi
        done
    done

    for d in "${!llc_order[@]}"; do
        ptr[$d]=0
    done
    progressed=1
    while [ "$progressed" -eq 1 ]; do
        progressed=0
        for d in "${!llc_order[@]}"; do
            read -r -a sibs <<< "${llc_smt[$d]}"
            if [ "${ptr[$d]}" -lt "${#sibs[@]}" ]; then
                ordered+=("${sibs[${ptr[$d]}]}")
                ptr[$d]=$((ptr[$d] + 1))
                progressed=1
            fi
        done
    done

    if [ "${#ordered[@]}" -eq 0 ]; then
        ordered=("${online[@]}")
    fi

    local i
    for ((i = 0; i < need; i++)); do
        echo "${ordered[$((i % ${#ordered[@]}))]}"
    done
}

link_worker_io() {
    # Prefer a hard link so workers share one page-cache copy of the
    # read-only witness; fall back to a symlink, then a copy.
    local src="$1"
    local dst="$2"
    if ln -f "$src" "$dst" 2>/dev/null; then
        return 0
    fi
    if ln -sfn "$src" "$dst" 2>/dev/null; then
        return 0
    fi
    cp -f "$src" "$dst"
}

prepare_mt_workdir() {
    # Prefer /dev/shm so VOLE/proof scratch files never hit disk under
    # many concurrent workers. Fall back to fennel/ when shm is missing
    # or too small. Prints: workdir keep_logs used_tmpfs
    local stamp="$1"
    local io_mode="$2"
    local threads="$3"
    local name="mt_${io_mode}_${stamp}"
    local keep="$TRUEPIX_ROOT/$name"
    local need_mb=$((threads * 256))
    local shm_free_mb=0
    local workdir="$keep"
    local used_tmpfs=0

    if [ -d /dev/shm ] && [ -w /dev/shm ]; then
        shm_free_mb="$(df -Pm /dev/shm 2>/dev/null | awk 'NR==2 {print $4}')"
        if [[ "$shm_free_mb" =~ ^[0-9]+$ ]] && [ "$shm_free_mb" -ge "$need_mb" ]; then
            workdir="/dev/shm/truepix_${name}_$$"
            used_tmpfs=1
        fi
    fi
    mkdir -p "$workdir" "$keep"
    printf '%s %s %s\n' "$workdir" "$keep" "$used_tmpfs"
}

finalize_mt_workdir() {
    local workdir="$1"
    local keep="$2"
    local used_tmpfs="$3"
    if [ "$used_tmpfs" -eq 1 ]; then
        local t
        for t in "$workdir"/thread_*.log; do
            [ -f "$t" ] || continue
            cp -f "$t" "$keep/"
        done
        rm -rf "$workdir"
    fi
}

# Print one CPU for the launcher shell and the CUDA MPS daemon: the slowest
# CPU whose physical core hosts no worker, else any CPU no worker uses.
# Prints nothing when every CPU is taken. $@ = worker CPUs.
pick_housekeeping_cpu() {
    local -A busy=() busy_core=()
    local c s path rank best="" best_rank="" spare=""
    for c in "$@"; do
        busy["$c"]=1
        for s in $(expand_cpu_list "$(cat "/sys/devices/system/cpu/cpu$c/topology/thread_siblings_list" 2>/dev/null || echo "$c")"); do
            busy_core["$s"]=1
        done
    done
    for path in /sys/devices/system/cpu/cpu[0-9]*; do
        c="${path##*/cpu}"
        [[ "$c" =~ ^[0-9]+$ ]] || continue
        if [ -f "$path/online" ] && [ "$(cat "$path/online" 2>/dev/null)" != "1" ]; then
            continue
        fi
        [ -z "${busy[$c]+x}" ] || continue
        if [ -n "${busy_core[$c]+x}" ]; then
            [ -n "$spare" ] || spare="$c"
            continue
        fi
        rank="$(cpu_perf_rank "$c")"
        if [ -z "$best" ] || [ "$rank" -lt "$best_rank" ] \
            || { [ "$rank" -eq "$best_rank" ] && [ "$c" -gt "$best" ]; }; then
            best="$c"
            best_rank="$rank"
        fi
    done
    if [ -n "$best" ]; then
        echo "$best"
    elif [ -n "$spare" ]; then
        echo "$spare"
    fi
}

# The H100 runs in Exclusive Process mode: only the first worker to create a
# CUDA context gets the GPU and the rest silently fall back to CPU GKR.
# A per-user MPS daemon owns the single context and serves every worker.
MPS_DIR=""
start_user_mps() {
    if ! command -v nvidia-cuda-mps-control >/dev/null 2>&1; then
        echo "Warning: nvidia-cuda-mps-control not found; only one worker can use the GPU"
        return 1
    fi
    MPS_DIR="/tmp/truepix_mps_$$"
    mkdir -p "$MPS_DIR/pipe" "$MPS_DIR/log"
    export CUDA_MPS_PIPE_DIRECTORY="$MPS_DIR/pipe"
    export CUDA_MPS_LOG_DIRECTORY="$MPS_DIR/log"
    if nvidia-cuda-mps-control -d; then
        echo "CUDA MPS: started per-user daemon ($CUDA_MPS_PIPE_DIRECTORY)"
        trap stop_user_mps EXIT
        trap 'stop_user_mps; exit 130' INT TERM
        return 0
    fi
    echo "Warning: failed to start CUDA MPS; only one worker can use the GPU"
    unset CUDA_MPS_PIPE_DIRECTORY CUDA_MPS_LOG_DIRECTORY
    rm -rf "$MPS_DIR"
    MPS_DIR=""
    return 1
}

stop_user_mps() {
    [ -n "$MPS_DIR" ] || return 0
    echo quit | nvidia-cuda-mps-control >/dev/null 2>&1 || true
    if [ -s "$MPS_DIR/log/control.log" ] && grep -qi "fail\|error" "$MPS_DIR/log/control.log"; then
        echo "CUDA MPS log: $MPS_DIR/log/control.log"
        tail -n 5 "$MPS_DIR/log/control.log"
    fi
    sleep 0.2
    rm -rf "$MPS_DIR"
    unset CUDA_MPS_PIPE_DIRECTORY CUDA_MPS_LOG_DIRECTORY
    MPS_DIR=""
}

# Reads one value per line; prints "min max max/min".
spread_stats() {
    awk 'NR == 1 { mn = $1; mx = $1 }
         { if ($1 < mn) mn = $1; if ($1 > mx) mx = $1 }
         END { printf "min %.6fs  max %.6fs  max/min %.3f\n", mn, mx, (mn > 0 ? mx / mn : 0) }'
}

run_random_multithread() {
    local frames=$1
    local threads=$2
    # Third arg is optional; final random MT always uses shared random IO.
    local io_mode="${3:-random}"
    local n_per=$((frames / threads))
    local ncpu
    ncpu=$(nproc 2>/dev/null || echo 1)
    local stamp
    stamp=$(date +%Y%m%d_%H%M%S)
    local pws_abs="$TRUEPIX_ROOT/$PWS_PATH"

    local workdir keep used_tmpfs
    read -r workdir keep used_tmpfs <<<"$(prepare_mt_workdir "$stamp" "$io_mode" "$threads")"

    local -a cpus=()
    mapfile -t cpus < <(select_worker_cpus "$threads")
    local nphys=0
    local cpu_path sib_min sib_line sib
    for cpu_path in /sys/devices/system/cpu/cpu[0-9]*; do
        [ -e "$cpu_path/topology/thread_siblings_list" ] || continue
        sib_line="$(cat "$cpu_path/topology/thread_siblings_list" 2>/dev/null || true)"
        sib_min=""
        while IFS= read -r sib; do
            if [ -z "$sib_min" ] || [ "$sib" -lt "$sib_min" ]; then
                sib_min="$sib"
            fi
        done < <(expand_cpu_list "$sib_line")
        cpu="${cpu_path##*/cpu}"
        if [ -n "$sib_min" ] && [ "$cpu" = "$sib_min" ]; then
            nphys=$((nphys + 1))
        fi
    done
    if [ "$nphys" -eq 0 ]; then
        nphys="$ncpu"
    fi

    echo "=== Multi-thread mode (${io_mode} IO) ==="
    echo "Frames: $frames  Threads: $threads  Runs per thread (n): $n_per"
    echo "Host CPUs: $ncpu  Physical cores: $nphys  Logs: $keep"
    if [ "$used_tmpfs" -eq 1 ]; then
        echo "Scratch:    $workdir (tmpfs)"
    else
        echo "Scratch:    $workdir (disk; /dev/shm missing or too small)"
    fi
    echo "Worker CPUs: ${cpus[*]}  (policy: ${TRUEPIX_WORKER_CPUS:+explicit}${TRUEPIX_WORKER_CPUS:-${TRUEPIX_CPU_POLICY:-spread}})"
    local -a ranks=()
    for cpu in "${cpus[@]}"; do
        ranks+=("$(cpu_perf_rank "$cpu")")
    done
    echo "Worker CPU perf rank: ${ranks[*]}"
    local gov epp
    gov="$(cat "/sys/devices/system/cpu/cpu${cpus[0]}/cpufreq/scaling_governor" 2>/dev/null || echo n/a)"
    epp="$(cat "/sys/devices/system/cpu/cpu${cpus[0]}/cpufreq/energy_performance_preference" 2>/dev/null || echo n/a)"
    echo "CPU governor: $gov  EPP: $epp"
    local hk_cpu
    hk_cpu="$(pick_housekeeping_cpu "${cpus[@]}")"
    if [ -n "$hk_cpu" ] && taskset -cp "$hk_cpu" "$$" >/dev/null 2>&1; then
        echo "Housekeeping CPU: $hk_cpu (launcher shell, CUDA MPS daemon; no worker shares its core)"
    else
        echo "Housekeeping CPU: none free (launcher shares worker cores)"
    fi
    if [ "$threads" -gt "$nphys" ] && [ "$threads" -le "$ncpu" ]; then
        echo "Warning: threads ($threads) exceed physical cores ($nphys); extra workers use SMT siblings"
    elif [ "$threads" -gt "$ncpu" ]; then
        echo "Warning: threads ($threads) exceed CPUs ($ncpu); extra workers share cores"
    fi

    local barrier_dir="$workdir/barrier"
    local shared_dir="$workdir/shared"
    mkdir -p "$barrier_dir" "$shared_dir"
    local prove_slots="${TRUEPIX_PROVE_SLOTS:-4}"
    if ! [[ "$prove_slots" =~ ^[0-9]+$ ]] || [ "$prove_slots" -lt 1 ]; then
        prove_slots=4
    fi
    if [ "$prove_slots" -gt "$threads" ]; then
        prove_slots="$threads"
    fi
    local warmup="${TRUEPIX_WARMUP:-1}"
    if ! [[ "$warmup" =~ ^[0-9]+$ ]]; then
        warmup=1
    fi
    local verify_barrier=1
    case "${TRUEPIX_VERIFY_BARRIER:-1}" in
        0|false|FALSE|no|NO|off|OFF) verify_barrier=0 ;;
    esac
    echo "Resident workers: one Python process per thread (imports once)"
    if [ "$verify_barrier" -eq 1 ]; then
        echo "Pipeline: commit-stagger -> all-signed barrier -> prove-slots=$prove_slots -> all-proved barrier -> verify"
    else
        echo "Pipeline: commit-stagger -> all-signed barrier -> prove-slots=$prove_slots -> verify"
    fi
    echo "Warm-up rounds per thread (excluded from sums): $warmup"

    if [ "$USE_GPU" = "1" ] && [ "$threads" -gt 1 ]; then
        case "${TRUEPIX_MPS:-1}" in
            0|false|FALSE|no|NO|off|OFF)
                echo "Warning: TRUEPIX_MPS=0; in Exclusive Process mode only one worker gets the GPU" ;;
            *) start_user_mps || true ;;
        esac
    fi

    local shared_input="" shared_output=""
    if [ "$io_mode" = "video" ]; then
        shared_input="$TRUEPIX_ROOT/input.txt"
        shared_output="$TRUEPIX_ROOT/output.txt"
    else
        echo "Preparing shared random input/output once (constraint $CONSTRAINT_SIZE)"
        if ! (
            cd "$shared_dir" || exit 1
            PYTHONPATH="$TRUEPIX_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
            TRUEPIX_CROP_REGION="${CROP_COORDS:-}" \
            TRUEPIX_MB_WIDTH="${MB_WIDTH:-}" \
            python3 - <<PY
from libTruePix.defs import Defs
from libTruePix.fp2_link import prepare_random_circuit_io
import os
Defs.configure()
kwargs = {"input_path": "input.txt", "output_path": "output.txt"}
crop = os.environ.get("TRUEPIX_CROP_REGION", "").strip()
mb_w = os.environ.get("TRUEPIX_MB_WIDTH", "").strip()
if crop:
    parts = crop.split()
    if len(parts) != 4:
        raise SystemExit("TRUEPIX_CROP_REGION must be: x1 x2 y1 y2")
    kwargs["crop_region"] = tuple(float(x) for x in parts)
if mb_w:
    kwargs["mb_width"] = int(mb_w)
info = prepare_random_circuit_io(
    "$pws_abs",
    int("$CONSTRAINT_SIZE"),
    **kwargs,
)
print("Prepared shared random IO:", info)
PY
        ); then
            echo "Error: failed to prepare shared random input/output"
            return 1
        fi
        shared_input="$shared_dir/input.txt"
        shared_output="$shared_dir/output.txt"
    fi
    if [ ! -f "$shared_input" ] || [ ! -f "$shared_output" ]; then
        echo "Error: shared input.txt / output.txt missing"
        return 1
    fi
    echo "Shared IO: $shared_input"

    local -a pids=()
    local -a logs=()
    local t cpu log
    for ((t = 0; t < threads; t++)); do
        cpu="${cpus[$t]}"
        log="$workdir/thread_${t}.log"
        link_worker_bins "$workdir/thread_${t}"
        link_worker_io "$shared_input" "$workdir/thread_${t}/input.txt"
        link_worker_io "$shared_output" "$workdir/thread_${t}/output.txt"
        logs+=("$log")
        (
            cd "$workdir/thread_${t}" || exit 1
            export TRUEPIX_CPU="$cpu"
            # One core per worker: any library thread pool would oversubscribe it.
            export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
                NUMEXPR_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1
            taskset -cp "$cpu" "$BASHPID" >/dev/null
            local worker_args=(
                --runs "$n_per"
                --thread-id "$t"
                --threads "$threads"
                --barrier "$barrier_dir"
                --pws "$pws_abs"
                -c "$CONSTRAINT_SIZE"
                -z "$USE_ZK"
                --reuse-io
                --prove-slots "$prove_slots"
                --warmup "$warmup"
                --verify-barrier "$verify_barrier"
            )
            PYTHONPATH="$TRUEPIX_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
                python3 "$TRUEPIX_ROOT/run_truepix_mt_worker.py" "${worker_args[@]}"
        ) >"$log" 2>&1 &
        pids+=("$!")
    done

    local fail=0
    local pid
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            fail=1
        fi
    done
    stop_user_mps

    echo
    echo "Per-thread sums over n=${n_per} runs (not summed across threads):"
    printf "%-8s %-6s %-5s %-22s %-22s %-22s\n" "thread" "cpu" "gkr" "TOTAL Signing Time" "TOTAL Prove Time" "TOTAL Verify Time"
    local -a sign_means=() prove_means=() verify_means=()
    local n_gpu=0 n_cpu_gkr=0
    for ((t = 0; t < threads; t++)); do
        local sign_line prove_line verify_line backend
        sign_line=$(sum_metric "${logs[$t]}" "TOTAL Signing Time")
        prove_line=$(sum_metric "${logs[$t]}" "TOTAL Prove Time")
        verify_line=$(sum_metric "${logs[$t]}" "TOTAL Verify Time")
        backend="$(sed -n 's/^Worker GKR backend: \([A-Z]*\).*/\1/p' "${logs[$t]}" | head -n 1)"
        [ -n "$backend" ] || backend="?"
        case "$backend" in
            GPU) n_gpu=$((n_gpu + 1)) ;;
            CPU) n_cpu_gkr=$((n_cpu_gkr + 1)) ;;
        esac
        local sign_sum sign_n prove_sum prove_n verify_sum verify_n
        read -r sign_sum sign_n <<<"$sign_line"
        read -r prove_sum prove_n <<<"$prove_line"
        read -r verify_sum verify_n <<<"$verify_line"
        printf "%-8s %-6s %-5s %-22s %-22s %-22s\n" \
            "$t" "${cpus[$t]}" "$backend" \
            "${sign_sum}s (n=${sign_n})" \
            "${prove_sum}s (n=${prove_n})" \
            "${verify_sum}s (n=${verify_n})"
        [ "$sign_n" -gt 0 ] && sign_means+=("$(awk -v s="$sign_sum" -v n="$sign_n" 'BEGIN { printf "%.6f", s / n }')")
        [ "$prove_n" -gt 0 ] && prove_means+=("$(awk -v s="$prove_sum" -v n="$prove_n" 'BEGIN { printf "%.6f", s / n }')")
        [ "$verify_n" -gt 0 ] && verify_means+=("$(awk -v s="$verify_sum" -v n="$verify_n" 'BEGIN { printf "%.6f", s / n }')")
        if [ "$sign_n" -ne "$n_per" ] || [ "$prove_n" -ne "$n_per" ] || [ "$verify_n" -ne "$n_per" ]; then
            echo "Thread $t: expected ${n_per} samples of each metric, see ${logs[$t]}"
            echo "----- ${logs[$t]} (tail) -----"
            tail -n 40 "${logs[$t]}"
            echo "----- end -----"
            fail=1
        fi
    done

    if [ "$threads" -gt 1 ]; then
        echo
        echo "Per-run mean across threads:"
        [ "${#sign_means[@]}" -gt 0 ] && echo "  Signing: $(printf '%s\n' "${sign_means[@]}" | spread_stats)"
        [ "${#prove_means[@]}" -gt 0 ] && echo "  Prove:   $(printf '%s\n' "${prove_means[@]}" | spread_stats)"
        [ "${#verify_means[@]}" -gt 0 ] && echo "  Verify:  $(printf '%s\n' "${verify_means[@]}" | spread_stats)"
        if [ "$USE_GPU" = "1" ] && [ "$n_gpu" -gt 0 ] && [ "$n_cpu_gkr" -gt 0 ]; then
            echo "Warning: mixed GKR backends ($n_gpu GPU, $n_cpu_gkr CPU); prove times are not comparable"
            echo "         (GPU is Exclusive Process; check CUDA MPS above, or use --no-gpu / --threads 1)"
        fi
    fi

    finalize_mt_workdir "$workdir" "$keep" "$used_tmpfs"

    if [ "$fail" -ne 0 ]; then
        echo "Multi-thread run failed. Logs: $keep"
        return 1
    fi
    echo "Multi-thread run completed. Logs: $keep"
    return 0
}


run_video_editing() {
    local input_video=$1
    local output_video=$2
    local operation=$3
    local crop_coords=$4

    echo "Running video editing operation: $operation"

    cd "$VIDEO_EDITION_DIR" || {
        echo "Error: Cannot change to VideoEdition directory"
        return 1
    }

    case $operation in
        "gray")
            python3 Video_Edition.py --input "$input_video" --output "$output_video" --gray
            ;;
        "invert"|"inv")
            python3 Video_Edition.py --input "$input_video" --output "$output_video" --invert
            ;;
        "mask")
            python3 Video_Edition.py --input "$input_video" --output "$output_video" --mask
            ;;
        "crop")
            python3 Video_Edition.py --input "$input_video" --output "$output_video" --crop $crop_coords
            ;;
        *)
            echo "Error: Unknown operation: $operation"
            cd "$TRUEPIX_ROOT"
            return 1
            ;;
    esac

    local edit_result=$?

    if [ $edit_result -eq 0 ]; then
        if [ -f "input.txt" ]; then
            mv -f "input.txt" "$TRUEPIX_ROOT/" 2>/dev/null
            echo "Moved input.txt to TruePix directory"
        fi

        if [ -f "output.txt" ]; then
            mv -f "output.txt" "$TRUEPIX_ROOT/" 2>/dev/null
            echo "Moved output.txt to TruePix directory"
        fi
        echo "Video editing completed successfully"
    else
        echo "Error: Video editing failed"
    fi

    cd "$TRUEPIX_ROOT" || return 1
    return $edit_result
}

INPUT_VIDEO=""
OUTPUT_VIDEO="output.mp4"
OPERATION=""
CONSTRAINT_SIZE=""
CROP_COORDS=""
MB_WIDTH=""
USE_RANDOM=0
USE_ZK=""
USE_GPU=""
FRAMES=""
THREADS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --input)
            INPUT_VIDEO="$2"
            shift 2
            ;;
        --output)
            OUTPUT_VIDEO="$2"
            shift 2
            ;;
        --operation)
            OPERATION="$2"
            shift 2
            ;;
        --constraint)
            CONSTRAINT_SIZE="$2"
            shift 2
            ;;
        --crop)
            if [ $# -ge 5 ]; then
                CROP_COORDS="$2 $3 $4 $5"
                shift 5
            else
                echo "Error: Crop operation requires 4 coordinates"
                usage
                exit 1
            fi
            ;;
        --mb-width)
            MB_WIDTH="$2"
            shift 2
            ;;
        --random)
            USE_RANDOM=1
            shift
            ;;
        --frames)
            FRAMES="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --zk)
            USE_ZK=1
            shift
            ;;
        --no-zk)
            USE_ZK=0
            shift
            ;;
        --gpu)
            USE_GPU=1
            shift
            ;;
        --no-gpu)
            USE_GPU=0
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

if [ -z "$OPERATION" ]; then
    echo "Error: Operation is required"
    usage
    exit 1
fi

# Default to full ZK (GKR product-mask + Orion_zk); --no-zk selects plain GKR + Orion_nonzk.
if [ -z "$USE_ZK" ]; then
    USE_ZK=1
fi

# GKR backend: --gpu uses the CUDA library when present; --no-gpu forces
# the CPU path used by TruePix_new_test_3s. Unset flag keeps the current
# default (GPU if libnative_fp2_gpu.so and a device exist).
if [ -z "$USE_GPU" ]; then
    case "${TRUEPIX_ENABLE_GPU:-}" in
        0|false|FALSE|no|NO|off|OFF) USE_GPU=0 ;;
        *) USE_GPU=1 ;;
    esac
fi
export TRUEPIX_ENABLE_GPU="$USE_GPU"
if [ "$USE_GPU" = "1" ]; then
    gpu_probe="$(
        PYTHONPATH="$TRUEPIX_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -c \
            'from libTruePix.native_fp2_bridge import GPU_ACTIVE, GPU_FAIL_REASON
print("1" if GPU_ACTIVE else "0")
print(GPU_FAIL_REASON)' \
            2>/dev/null || printf '0\nprobe failed\n'
    )"
    gpu_status="$(printf '%s\n' "$gpu_probe" | sed -n '1p')"
    gpu_reason="$(printf '%s\n' "$gpu_probe" | sed -n '2p')"
    if [ "$gpu_status" = "1" ]; then
        echo "GKR backend: GPU active (libnative_fp2_gpu.so + CUDA device)"
    else
        echo "GKR backend: CPU fallback (TRUEPIX_ENABLE_GPU=1 but GPU not active)"
        [ -n "$gpu_reason" ] && echo "  reason: $gpu_reason"
    fi
else
    echo "GKR backend: CPU (TRUEPIX_ENABLE_GPU=0; 3s-compatible host path)"
fi

if [ "$USE_RANDOM" -eq 0 ] && [ -z "$INPUT_VIDEO" ]; then
    echo "Error: Input video is required in non-random mode"
    usage
    exit 1
fi

if [ "$USE_RANDOM" -eq 0 ] && [ ! -f "$INPUT_VIDEO" ]; then
    if [ ! -f "../VideoEdition/$INPUT_VIDEO" ]; then
        echo "Error: Input video file not found: $INPUT_VIDEO"
        echo "Also tried: ../VideoEdition/$INPUT_VIDEO"
        exit 1
    else
        INPUT_VIDEO="../VideoEdition/$INPUT_VIDEO"
        echo "Found input video at: $INPUT_VIDEO"
    fi
fi

if [ "$OPERATION" = "crop" ] && [ -z "$CROP_COORDS" ] && [ "$USE_RANDOM" -eq 0 ]; then
    echo "Error: Crop operation requires crop coordinates"
    usage
    exit 1
fi

PWS_PATH=$(get_pws_path "$OPERATION")

if [ ! -f "$PWS_PATH" ]; then
    echo "Error: PWS file not found: $PWS_PATH"
    echo "Available PWS files in pws/:"
    ls -la "pws/" 2>/dev/null || echo "PWS directory not found or empty"
    exit 1
fi

echo "Using PWS file: $PWS_PATH"

if [ -z "$CONSTRAINT_SIZE" ] && [ "$USE_RANDOM" -eq 0 ]; then
    echo "Auto-calculating constraint size after video editing..."
    if ! run_video_editing "$INPUT_VIDEO" "$OUTPUT_VIDEO" "$OPERATION" "$CROP_COORDS"; then
        echo "Error: Video editing phase failed, cannot calculate constraint size"
        exit 1
    fi
    CONSTRAINT_SIZE=$(calculate_constraint_size "input.txt")
    echo "Auto-calculated constraint size: $CONSTRAINT_SIZE"
    VIDEO_EDIT_DONE=1
elif [ -z "$CONSTRAINT_SIZE" ]; then
    CONSTRAINT_SIZE="1200"
    echo "Using default constraint size for random mode: $CONSTRAINT_SIZE"
    VIDEO_EDIT_DONE=0
else
    VIDEO_EDIT_DONE=0
fi

if ! [[ "$CONSTRAINT_SIZE" =~ ^[0-9]+$ ]] || [ "$CONSTRAINT_SIZE" -le 0 ]; then
    echo "Error: Constraint size must be a positive integer"
    usage
    exit 1
fi

echo "Using constraint size: $CONSTRAINT_SIZE"

if [ -n "$FRAMES" ] || [ -n "$THREADS" ]; then
    if [ -z "$FRAMES" ] || [ -z "$THREADS" ]; then
        echo "Error: --frames and --threads must be set together"
        usage
        exit 1
    fi
    if ! [[ "$FRAMES" =~ ^[0-9]+$ ]] || ! [[ "$THREADS" =~ ^[0-9]+$ ]] \
        || [ "$FRAMES" -le 0 ] || [ "$THREADS" -le 0 ]; then
        echo "Error: --frames and --threads must be positive integers"
        usage
        exit 1
    fi
    if [ $((FRAMES % THREADS)) -ne 0 ]; then
        echo "Error: total frames ($FRAMES) must be divisible by threads ($THREADS)"
        usage
        exit 1
    fi
    mt_io_mode=random
    if [ "$USE_RANDOM" -ne 1 ]; then
        if [ "${VIDEO_EDIT_DONE:-0}" -ne 1 ]; then
            if ! run_video_editing "$INPUT_VIDEO" "$OUTPUT_VIDEO" "$OPERATION" "$CROP_COORDS"; then
                echo "Error: Video editing phase failed, skipping TruePix proofs"
                exit 1
            fi
        else
            echo "Using input/output produced by video editing"
        fi
        if [ ! -f "$TRUEPIX_ROOT/input.txt" ] || [ ! -f "$TRUEPIX_ROOT/output.txt" ]; then
            echo "Error: video editing did not produce input.txt and output.txt"
            exit 1
        fi
        mt_io_mode=video
    fi
    run_random_multithread "$FRAMES" "$THREADS" "$mt_io_mode"
    mt_status=$?
    if [ "$mt_status" -eq 0 ]; then
        echo "TruePix processing completed successfully!"
    else
        echo "TruePix processing failed!"
        exit 1
    fi
    exit 0
fi

if [ "$USE_RANDOM" -eq 1 ]; then
    echo "=== Random Input Testing Mode ==="
    run_truepix_proofs_optimized "$OPERATION" "1" "$USE_ZK" "$PWS_PATH" "$CONSTRAINT_SIZE"
else
    echo "=== Video Editing Mode ==="
    if [ "${VIDEO_EDIT_DONE:-0}" -ne 1 ]; then
        if ! run_video_editing "$INPUT_VIDEO" "$OUTPUT_VIDEO" "$OPERATION" "$CROP_COORDS"; then
            echo "Error: Video editing phase failed, skipping TruePix proofs"
            exit 1
        fi
    else
        echo "Using input/output produced by video editing"
    fi
    run_truepix_proofs_optimized "$OPERATION" "0" "$USE_ZK" "$PWS_PATH" "$CONSTRAINT_SIZE"
fi

if [ $? -eq 0 ]; then
    echo "TruePix processing completed successfully!"
else
    echo "TruePix processing failed!"
    exit 1
fi
