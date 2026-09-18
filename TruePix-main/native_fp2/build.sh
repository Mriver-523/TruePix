#!/usr/bin/env bash
# Build Orion-backed native_fp2 shared library for TruePix GKR.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
ORION_INC="$ROOT/../Orion/Orion_zk/include"
ORION_SRC="$ROOT/../Orion/Orion_zk/src/linear_gkr/prime_field.cpp"
OUT="$ROOT/lib/libnative_fp2.so"

mkdir -p "$ROOT/lib"
g++ -shared -fPIC -O3 -march=native -std=c++17 \
  -I"$ORION_INC" \
  "$ROOT/native_fp2.cpp" \
  "$ORION_SRC" \
  -o "$OUT"

echo "Built $OUT"
