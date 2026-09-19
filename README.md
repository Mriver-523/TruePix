# TruePix: Fast and Memory-Efficient Zero-Knowledge Authentication for Images and Videos

## Overview

TruePix is a protocol prototype for verifiable images and videos editing.
This implementation combines:

- a video processing pipeline in Python and C++ (via FFmpeg) ;
- a multi-linear polynomial commitment to the input layer;
- the GKR protocol for circuits;
- QuickSilver as the outer, VOLE-based zero-knowledge proof system;
- commit-then-sign with ECDSA signatures over group commitments.

The repository is intended for research and performance evaluation, not production deployment.

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

## Build

Install prerequisites above first, then from the **repository root** run one
compile script (Hyrax native libs, Orion binaries, `native_fp2`, and `fft_gkr`):

```bash
./setup.sh
```

## Repository Layout Assumption

`TruePix.sh` expects the video editing module at:

```text
../VideoEdition
```

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

Random mode on several cores. `--frames` is the total number of frames and `--threads` is the number of workers. Each worker is pinned to its own core and runs `n = frames / threads` times. The script then prints, for each thread, the sum of `TOTAL Signing Time`, `TOTAL Prove Time`, and `TOTAL Verify Time` over those `n` runs:

```bash
./TruePix.sh --random --operation gray --constraint 1350 --frames 8 --threads 4
```

