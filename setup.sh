#!/usr/bin/env bash
# One-shot build for a fresh TruePix checkout (compile only).
# Install system packages and `pip install -r requirements.txt` first
# (see README Prerequisites), then:
#   ./setup.sh
# After it finishes:
#   cd TruePix-main && ./TruePix.sh --help

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUEPIX="$ROOT/TruePix-main"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: '$1' not found. Install prerequisites listed in README.md first."
        exit 1
    fi
}

echo "TruePix setup (compile only)"
echo "Repo root: $ROOT"
echo

need_cmd make
need_cmd g++
need_cmd cmake
need_cmd xsltproc
need_cmd python3

echo "========== 1/3 Hyrax native libs (libpws, pymiracl) =========="
"$ROOT/scripts/build_native_deps.sh"

echo
echo "========== 2/3 Orion binaries =========="
(
    cd "$TRUEPIX"
    ./Orion_generate.sh
)

echo
echo "========== 3/3 native_fp2 + fft_gkr =========="
(
    cd "$TRUEPIX"
    ./native_fp2/build.sh
)

# Orion VPD calls "./fft_gkr" from the TruePix working directory.
if [ ! -x "$TRUEPIX/fft_gkr" ]; then
    if [ -f "$TRUEPIX/Orion/Orion_zk/fft_gkr" ]; then
        cp -f "$TRUEPIX/Orion/Orion_zk/fft_gkr" "$TRUEPIX/fft_gkr"
    elif [ -f "$TRUEPIX/Orion/Orion_nonzk/fft_gkr" ]; then
        cp -f "$TRUEPIX/Orion/Orion_nonzk/fft_gkr" "$TRUEPIX/fft_gkr"
    else
        echo "Error: fft_gkr binary not found under TruePix-main/ or Orion_*"
        exit 1
    fi
fi
chmod +x "$TRUEPIX/fft_gkr"
echo "fft_gkr ready: $TRUEPIX/fft_gkr"

echo
echo "========== Smoke checks =========="
(
    cd "$TRUEPIX"
    # pypws / pymiracl are cffi packages under libpws/python and
    # pymiracl/python; they are on no default sys.path.
    PYTHONPATH="$ROOT/libpws/python:$ROOT/pymiracl/python${PYTHONPATH:+:$PYTHONPATH}" \
        python3 -c "import pypws; import pymiracl; print('pypws + pymiracl OK')"
    test -x ./linearPC_multi_commit_zk
    test -x ./linearPC_multi_prove_zk
    test -x ./linearPC_multi_open_zk
    test -x ./linearPC_multi_commit
    test -x ./linearPC_multi_prove
    test -x ./linearPC_multi_open
    test -x ./fft_gkr
    test -f ./native_fp2/lib/libnative_fp2.so
    echo "Orion binaries + fft_gkr + native_fp2 OK"
)

echo
echo "Setup complete."
echo "You can now run:"
echo "  cd TruePix-main"
echo "  ./TruePix.sh --random --operation gray --constraint 1350"
echo "  # or with a video:"
echo "  ./TruePix.sh --input input.mp4 --operation gray"
