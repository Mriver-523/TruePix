#!/usr/bin/env bash
# Build Hyrax native Python extensions required by TruePix:
#   libpws  -> python/pypws/lib/pylibpws.so
#   pymiracl -> python/pymiracl/lib/pymiracl.so
#
# Prefer ./setup.sh from the repository root for a full install.
# This script remains for incremental rebuilds of libpws/pymiracl only.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: '$1' not found. On Debian/Ubuntu install: sudo apt install -y $2"
        exit 1
    fi
}

link_so() {
    local built=$1
    local dest=$2
    if [ ! -e "$built" ]; then
        echo "Error: expected shared library not found: $built"
        return 1
    fi
    mkdir -p "$(dirname "$dest")"
    local rel
    rel="$(realpath --relative-to="$(dirname "$dest")" "$built")"
    ln -sfn "$rel" "$dest"
    echo "Linked $dest -> $rel"
}

build_autotools_pkg() {
    local name=$1
    local dir="$ROOT/$name"
    local so_src=$2
    local so_dst=$3

    echo "=== Building $name ==="
    if [ ! -d "$dir" ]; then
        echo "Error: $dir not found"
        return 1
    fi

    (
        cd "$dir"
        if [ ! -f configure ]; then
            need_cmd autoreconf "autoconf automake libtool"
            ./autogen.sh
        fi
        if [ ! -f Makefile ]; then
            ./configure
        fi
        make -j"$JOBS"
    )

    link_so "$dir/$so_src" "$dir/$so_dst"
}

need_cmd make "build-essential"
need_cmd g++ "build-essential"
need_cmd pkg-config "pkg-config"

build_autotools_pkg \
    libpws \
    "src/pylibpws/.libs/pylibpws.so" \
    "python/pypws/lib/pylibpws.so"

build_autotools_pkg \
    pymiracl \
    "src/pymiracl/.libs/pymiracl.so" \
    "python/pymiracl/lib/pymiracl.so"

echo "Native deps ready."
(
    cd "$ROOT/TruePix-main"
    # pypws / pymiracl are cffi packages under libpws/python and
    # pymiracl/python; they are on no default sys.path.
    PYTHONPATH="$ROOT/libpws/python:$ROOT/pymiracl/python${PYTHONPATH:+:$PYTHONPATH}" \
        python3 -c "import pypws; import pymiracl; print('pypws + pymiracl OK')"
)
