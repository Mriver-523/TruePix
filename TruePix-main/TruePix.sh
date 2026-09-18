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
    echo "  --crop <x1> <x2> <y1> <y2> Crop coordinates 0-1 (for crop operation)"
    echo "  --random                  Use random input for testing (skip video editing)"
    echo "  --zk                      Enable full ZK (GKR product-mask + Orion mask/masked; default)"
    echo "  --no-zk                   Disable ZK (plain GKR VOLE + Orion single polynomial)"
    echo "  --help                    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --input input.mp4 --operation gray --zk"
    echo "  $0 --input input.mp4 --operation crop --crop 0.2 0.8 0.2 0.8"
    echo "  $0 --random --operation gray --constraint 1350"
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
        if ! PYTHONPATH=. python3 - <<PY
from libTruePix.defs import Defs
from libTruePix.fp2_link import prepare_random_circuit_io
Defs.configure()
info = prepare_random_circuit_io("$pws_file", int("$constraint_size"))
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
USE_RANDOM=0
USE_ZK=""

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
        --random)
            USE_RANDOM=1
            shift
            ;;
        --zk)
            USE_ZK=1
            shift
            ;;
        --no-zk)
            USE_ZK=0
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
