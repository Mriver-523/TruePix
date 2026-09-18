#!/bin/bash
# Compile both Orion trees and install six binaries into the TruePix root:
#   linearPC_multi_{commit,prove,open}       from Orion_nonzk
#   linearPC_multi_{commit,prove,open}_zk    from Orion_zk
#
# Fresh checkouts do not include libXKCP.a / libflo-shani.a (they are gitignored
# build artifacts). This script builds them from the vendored sources under
# include/XKCP and include/flo-shani-aesni when missing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUEPIX_ROOT="$SCRIPT_DIR"

echo "Starting Orion setup process..."
echo "TruePix root directory: $TRUEPIX_ROOT"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command '$1' not found."
        echo "On Debian/Ubuntu: sudo apt install -y $2"
        exit 1
    fi
}

# Pick an XKCP ISA target. Prefer AVX2 (matches the previously shipped archives);
# fall back to portable generic64 when AVX2 is unavailable.
select_xkcp_target() {
    if [ -n "${XKCP_TARGET:-}" ]; then
        echo "$XKCP_TARGET"
        return
    fi
    if grep -qw avx2 /proc/cpuinfo 2>/dev/null; then
        echo "AVX2"
    else
        echo "generic64"
    fi
}

build_flo_shani() {
    local src_dir=$1
    local out_lib="$src_dir/lib/libflo-shani.a"
    local flo_dir="$src_dir/include/flo-shani-aesni"

    if [ -f "$out_lib" ]; then
        return 0
    fi

    echo "Building libflo-shani.a from $flo_dir ..."
    if [ ! -d "$flo_dir" ]; then
        echo "Error: flo-shani sources not found at $flo_dir"
        return 1
    fi

    mkdir -p "$src_dir/lib" "$flo_dir/lib"
    if [ ! -f "$flo_dir/Makefile" ]; then
        echo "Error: missing $flo_dir/Makefile (vendored flo-shani build file)."
        echo "Run git pull, or ensure Orion .gitignore no longer excludes source Makefiles."
        return 1
    fi
    # Only the SHA library is required; skip OpenSSL-dependent benches.
    # Create lib/ ourselves — do not rely on the Makefile 'folder' target.
    make -C "$flo_dir" lib/libflo-shani.a
    cp -f "$flo_dir/lib/libflo-shani.a" "$out_lib"
    echo "Installed $out_lib"
}

build_xkcp() {
    local src_dir=$1
    local out_lib="$src_dir/lib/libXKCP.a"
    local xkcp_dir="$src_dir/include/XKCP"
    local target
    target="$(select_xkcp_target)"

    if [ -f "$out_lib" ]; then
        return 0
    fi

    echo "Building libXKCP.a (target=$target) from $xkcp_dir ..."
    if [ ! -d "$xkcp_dir" ]; then
        echo "Error: XKCP sources not found at $xkcp_dir"
        return 1
    fi

    need_cmd xsltproc "xsltproc"
    need_cmd make "build-essential"

    mkdir -p "$src_dir/lib"
    make -C "$xkcp_dir" "${target}/libXKCP.a"

    local built_lib="$xkcp_dir/bin/${target}/libXKCP.a"
    local built_hdr="$xkcp_dir/bin/${target}/libXKCP.a.headers"
    if [ ! -f "$built_lib" ]; then
        echo "Error: expected $built_lib after XKCP build"
        return 1
    fi

    cp -f "$built_lib" "$out_lib"
    if [ -d "$built_hdr" ]; then
        rm -rf "$src_dir/lib/libXKCP.a.headers"
        cp -a "$built_hdr" "$src_dir/lib/libXKCP.a.headers"
    fi
    echo "Installed $out_lib (XKCP target=$target)"
}

ensure_static_libs() {
    local src_dir=$1
    build_flo_shani "$src_dir"
    build_xkcp "$src_dir"

    if [ ! -f "$src_dir/lib/libXKCP.a" ] || [ ! -f "$src_dir/lib/libflo-shani.a" ]; then
        echo "Error: missing static libs in $src_dir/lib (need libXKCP.a and libflo-shani.a)"
        return 1
    fi
}

compile_version() {
    local dir_name=$1
    local is_zk=$2
    local src_dir="$TRUEPIX_ROOT/Orion/$dir_name"
    # A dedicated build dir avoids stale CMakeCache entries that still point
    # at a previous checkout path.
    local build_dir="$src_dir/build_tp"

    echo "Compiling $dir_name version..."

    if [ ! -d "$src_dir" ]; then
        echo "Error: Directory $src_dir does not exist"
        return 1
    fi

    # Drop stale caches (e.g. copied from another machine / checkout path).
    if [ -f "$build_dir/CMakeCache.txt" ]; then
        cached="$(grep -E '^CMAKE_HOME_DIRECTORY:' "$build_dir/CMakeCache.txt" | head -1 | cut -d= -f2- || true)"
        if [ -n "$cached" ] && [ "$cached" != "$src_dir" ]; then
            echo "Stale CMake cache points to $cached; cleaning $build_dir"
            rm -rf "$build_dir"
        fi
    fi

    ensure_static_libs "$src_dir"

    need_cmd cmake "cmake"
    mkdir -p "$build_dir"
    # CMakeLists uses -Llib relative to the build directory, not the source tree.
    ln -sfn "$src_dir/lib" "$build_dir/lib"
    cmake -S "$src_dir" -B "$build_dir"

    if [ "$is_zk" = "zk" ]; then
        cmake --build "$build_dir" -j --target \
            linearPC_multi_commit_zk \
            linearPC_multi_prove_zk \
            linearPC_multi_open_zk
        cp -f "$build_dir/linearPC_multi_commit_zk" "$TRUEPIX_ROOT/"
        cp -f "$build_dir/linearPC_multi_prove_zk" "$TRUEPIX_ROOT/"
        cp -f "$build_dir/linearPC_multi_open_zk" "$TRUEPIX_ROOT/"
    else
        cmake --build "$build_dir" -j --target \
            linearPC_multi_commit \
            linearPC_multi_prove \
            linearPC_multi_open
        cp -f "$build_dir/linearPC_multi_commit" "$TRUEPIX_ROOT/"
        cp -f "$build_dir/linearPC_multi_prove" "$TRUEPIX_ROOT/"
        cp -f "$build_dir/linearPC_multi_open" "$TRUEPIX_ROOT/"
    fi

    echo "$dir_name compilation completed successfully"
}

need_cmd make "build-essential"
need_cmd g++ "build-essential"

compile_version "Orion_zk" "zk"
compile_version "Orion_nonzk" "nonzk"

echo "Orion setup completed!"
echo "Generated binaries have been copied to: $TRUEPIX_ROOT"
echo "Available binaries:"
ls -la "$TRUEPIX_ROOT"/linearPC_multi_{commit,prove,open}{,_zk}

# Orion VPD calls "./fft_gkr" from the TruePix working directory.
if [ ! -x "$TRUEPIX_ROOT/fft_gkr" ]; then
    if [ -f "$TRUEPIX_ROOT/Orion/Orion_zk/fft_gkr" ]; then
        cp -f "$TRUEPIX_ROOT/Orion/Orion_zk/fft_gkr" "$TRUEPIX_ROOT/fft_gkr"
    elif [ -f "$TRUEPIX_ROOT/Orion/Orion_nonzk/fft_gkr" ]; then
        cp -f "$TRUEPIX_ROOT/Orion/Orion_nonzk/fft_gkr" "$TRUEPIX_ROOT/fft_gkr"
    fi
fi
if [ -f "$TRUEPIX_ROOT/fft_gkr" ]; then
    chmod +x "$TRUEPIX_ROOT/fft_gkr"
    echo "fft_gkr: $TRUEPIX_ROOT/fft_gkr"
fi
