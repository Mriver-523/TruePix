# TruePix - Video Image Editing Proof Protocol

## Overview

TruePix is a protocol prototype for verifiable video editing.
This implementation combines:

- video transformation preprocessing (Python + FFmpeg),
- circuit proof generation and verification (Hyrax/TruePix-based components),
- input-equivalence proof components (Orion-based binaries),
- signature generation and verification over the Orion commitment manifest.

The repository is intended for research and performance evaluation, not production deployment.

## Experimental Environment

The numbers reported in the paper were collected in a virtual machine with:

- **8 vCPUs** and **8 GB RAM**
- Host CPU: **Intel Core i7-13700H (2.40 GHz)**
- Guest OS: Linux (Ubuntu-like)

For artifact evaluation, a similar x86-64 Linux VM (or bare metal) with at
least **8 GB RAM** is recommended. AVX2-capable CPUs are preferred (XKCP /
flo-shani builds default to AVX2 when available).

## Prerequisites

- Linux environment (tested on Ubuntu-like systems)
- Python 3 and `pip`
- C/C++ toolchain for native components
- FFmpeg runtime

Install system packages and Python dependencies from the repository root:

```bash
sudo apt update
sudo apt install -y ffmpeg build-essential g++ gcc automake autoconf pkg-config libtool \
  libtool-bin cmake xsltproc python3 python3-pip python3-cffi pypy3 \
  libssl-dev libgmp-dev
pip install -r requirements.txt
```

`cmake` and `xsltproc` are required by Orion / XKCP builds inside `./setup.sh`.

## Build

Install prerequisites above first, then from the **repository root** run one
compile script (Hyrax native libs, Orion binaries, `native_fp2`, and `fft_gkr`):

```bash
./setup.sh
```

Then use TruePix:

```bash
cd TruePix-main
./TruePix.sh --help
```

Lower-level scripts (`scripts/build_native_deps.sh`, `TruePix-main/Orion_generate.sh`,
`TruePix-main/native_fp2/build.sh`) remain available for incremental rebuilds, but
are not required for a fresh checkout.


## Repository Layout Assumption

`TruePix.sh` expects the video editing module at:

```text
../VideoEdition
```

In non-random mode, input videos are resolved from the given path or from
`../VideoEdition/<file>` (for example `--input input.mp4` finds
`../VideoEdition/input.mp4`).

Shared circuit I/O files `input.txt` / `output.txt` are written into `TruePix-main/`
after video editing (or prepared automatically in `--random` mode).

## Basic Usage

All commands below are run from `TruePix-main/`.

End-to-end pipeline:

```bash
./TruePix.sh [OPTIONS]
```

Show help:

```bash
./TruePix.sh --help
```

Zero-knowledge mode is enabled by default (`--zk`). Use `--no-zk` for the
plain GKR + non-ZK Orion path (the two settings compared in Table 1).

### Common Examples

Gray operation on a video (ZK default):

```bash
./TruePix.sh --input input.mp4 --operation gray --zk
```

Crop operation (coordinates are fractions in `[0, 1]`: `x1 x2 y1 y2`):

```bash
./TruePix.sh --input input.mp4 --operation crop --crop 0.2 0.8 0.2 0.8
```

Random-input benchmark mode (skips video preprocessing; still produces a shared
`input.txt` / `output.txt` pair before proving):

```bash
./TruePix.sh --random --operation gray --constraint 1350
```

Non-ZK variant of the same random benchmark:

```bash
./TruePix.sh --random --operation gray --constraint 1350 --no-zk
```

## Operation and PWS Mapping

The script selects PWS files by operation name:

- `gray` -> `pws/gray.pws`
- `invert` -> `pws/inv.pws`
- `mask` -> `pws/mask.pws`
- `crop` -> `pws/Crop.pws`

## License

This repository is a multi-license tree. See the root [`LICENSE`](LICENSE)
and [`NOTICE`](NOTICE) for a component-by-component summary.

TruePix protocol code (Hyrax-derived) lives under `TruePix-main/`:

- Full Apache-2.0 text + dual copyright: [`TruePix-main/LICENSE`](TruePix-main/LICENSE)
- Short attribution / provenance: [`TruePix-main/NOTICE`](TruePix-main/NOTICE)

In short:

- **TruePix core** (`TruePix-main/`, `VideoEdition/`): Apache-2.0 **derivative of
  [Hyrax](https://github.com/hyraxZK)**. Keep both copyright lines:
  Hyrax authors (original) and TruePix authors (modifications / new code).
- `libpws/`, `pylaurent/`, and Orion sources: Apache-2.0
- `pymiracl/`: **AGPL-3.0** (see `pymiracl/LICENSE`)

Redistributing or deploying a combined build that includes `pymiracl` may
trigger AGPL-3.0 obligations. Review that license before redistribution.

Vendored third-party trees (for example under `TruePix-main/Orion/*/include/`)
keep their upstream licenses. This repository vendors those sources as a
plain directory tree; no `git submodule` checkout is required.

# TruePix
