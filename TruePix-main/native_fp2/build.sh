#!/usr/bin/env bash
# Build native_fp2 shared libraries for TruePix GKR (fp61 arithmetic; no Orion link).
# Always builds libnative_fp2.so (CPU host). When nvcc is present, also builds
# libnative_fp2_gpu.so. Runtime uses the GPU library only if a device is
# available (see GPU_ACTIVE in libTruePix/native_fp2_bridge.py).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/lib/libnative_fp2.so"
GPU_OUT="$ROOT/lib/libnative_fp2_gpu.so"

mkdir -p "$ROOT/lib"
CXXFLAGS=(-O3 -std=c++17 -I"$ROOT")

echo "Building CPU native_fp2 (fp61 host arithmetic)"
g++ -shared -fPIC "${CXXFLAGS[@]}" -march=native \
  "$ROOT/native_fp2.cpp" \
  -o "$OUT"
echo "Built $OUT"

ARCH="${CUDA_ARCH:-sm_90}"
CUDA_HOME="${CUDA_HOME:-$(dirname "$(dirname "$(command -v nvcc)")")}"
if command -v nvcc >/dev/null 2>&1; then
  echo "Building GPU native_fp2 with nvcc (-arch=${ARCH})"
  nvcc -shared -Xcompiler -fPIC "${CXXFLAGS[@]}" \
    -arch="${ARCH}" \
    -Xlinker -rpath="${CUDA_HOME}/lib64" \
    "$ROOT/native_fp2.cu" \
    -o "$GPU_OUT" \
    -L"${CUDA_HOME}/lib64" \
    -lcudart
  echo "Built $GPU_OUT"
else
  echo "nvcc not found; skipping GPU library (CPU path unchanged)"
fi
