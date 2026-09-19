#!/usr/bin/env bash
# Build native_fp2 shared libraries for TruePix GKR.
# Always builds the Orion-backed CPU library. When nvcc is present, also
# builds libnative_fp2_gpu.so. Runtime uses the GPU library only if a device
# is available (see ENABLE_GPU in libTruePix/native_fp2_bridge.py).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
ORION_INC="$ROOT/../Orion/Orion_zk/include"
ORION_SRC="$ROOT/../Orion/Orion_zk/src/linear_gkr/prime_field.cpp"
OUT="$ROOT/lib/libnative_fp2.so"
GPU_OUT="$ROOT/lib/libnative_fp2_gpu.so"

mkdir -p "$ROOT/lib"
g++ -shared -fPIC -O3 -march=native -std=c++17 \
  -I"$ORION_INC" \
  "$ROOT/native_fp2.cpp" \
  "$ORION_SRC" \
  -o "$OUT"
echo "Built $OUT"

ARCH="${CUDA_ARCH:-sm_90}"
if command -v nvcc >/dev/null 2>&1; then
  echo "Building GPU native_fp2 with nvcc (-arch=${ARCH})"
  nvcc -shared -Xcompiler -fPIC -O3 -std=c++17 \
    -I"$ROOT" \
    -arch="${ARCH}" \
    "$ROOT/native_fp2.cu" \
    -o "$GPU_OUT" \
    -lcudart
  echo "Built $GPU_OUT"
else
  echo "nvcc not found; skipping GPU library (CPU path unchanged)"
fi
