#!/usr/bin/python3
"""
Helpers for protocol truepix: shared input, point I/O, Orion open wrapper.

Legacy callers are unaffected unless they import and use these helpers.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

from libTruePix.extfield import BASE_PRIME_61, Fp2, deserialize_point, serialize_point


LAYOUT_ID = "copy-major-384-const128-pad512-v1"
PROTOCOL_ID = "truepix"

# Written by linearPC_multi_commit_zk (the commit phase). Holds the layout the
# commitment was made over plus the two Merkle roots.
ORION_COMMIT_FILE = "orion_commit.json"
# Prover-side secret: the seed the mask polynomial is derived from, so that the
# commit, prove and open phases all use the same mask.
ORION_MASK_SEED_FILE = "orion_mask_seed.txt"
ORION_PROOF_FILE = "orion_proof.bin"
ORION_PROOF_MASKED_FILE = "orion_proof_masked.bin"
ORION_PROOF_MASK_FILE = "orion_proof_mask.bin"

_PROTOCOL_ALIASES = {PROTOCOL_ID, "fp2-linked-v1", "truepix"}

_MANIFEST_INT_FIELDS = (
    "copies",
    "padded_copies",
    "copy_size",
    "padded_copy_size",
    "const_idx",
    "const_val",
    "n",
    "lg_n",
)


@dataclass
class PendingInputClaim:
    input_point: List[Fp2]
    authenticated_claim: object
    n_copies: int
    n_in_bits: int


@dataclass
class OrionOpenResult:
    ok: bool
    value: Optional[Fp2]
    raw_stdout: str = ""
    verification_time: Optional[float] = None


def write_point_file(path: str, point: Sequence[Fp2], layout: str = LAYOUT_ID):
    payload = {
        "protocol": PROTOCOL_ID,
        "field": "fp2-mersenne61",
        "layout": layout,
        "point": serialize_point(point),
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)

    # Companion plaintext format for the C++ Orion binary (no JSON dependency).
    txt_path = path if path.endswith(".txt") else (os.path.splitext(path)[0] + ".txt")
    with open(txt_path, "w") as fh:
        fh.write("%d\n" % len(point))
        for elm in point:
            fh.write("%d %d\n" % (elm.real, elm.imag))
    return path, txt_path


def read_point_file(path: str) -> List[Fp2]:
    with open(path, "r") as fh:
        data = json.load(fh)
    if data.get("protocol") not in _PROTOCOL_ALIASES:
        raise ValueError("point file protocol mismatch")
    return deserialize_point(data["point"], BASE_PRIME_61)


def write_orion_result_file(path: str, result: OrionOpenResult):
    payload = {
        "ok": bool(result.ok),
        "value": None if result.value is None else result.value.serialize(),
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)


def parse_orion_verification_time(stdout: str) -> Optional[float]:
    """
    Sum all 'Verification time' lines from linearPC.cpp open_and_verify.

    Non-ZK prints one line; ZK serial mask+masked openings print two, and Input
    Verify Time should count both.
    """
    total = 0.0
    found = False
    for line in stdout.splitlines():
        if "Verification time" not in line:
            continue
        try:
            total += float(line.split()[-1])
            found = True
        except ValueError:
            pass
    return total if found else None


def parse_orion_prove_time(stdout: str) -> Optional[float]:
    """
    Sum Orion prove/open wall time for Input Prove Time:
      internal Commit time(s) + Open time(s).

    The prove binary re-commits before opening; that commit cost is part of the
    prove-phase work and is included here. Signer-phase Input Commit Time is
    reported separately and is not double-counted (different process stdout).

    Non-ZK prints one Commit + one Open. ZK prints one fused Commit time(mask)
    (both polynomials) plus two Open times. Streaming re-encode is reported as
    'Encode preprocess time' and is already excluded from the printed Open time.
    """
    total = 0.0
    found = False
    for line in stdout.splitlines():
        if "Open time" not in line and "Commit time" not in line:
            continue
        try:
            total += float(line.split()[-1])
            found = True
        except ValueError:
            pass
    return total if found else None

def parse_orion_proof_size(stdout: str) -> Optional[int]:
    """
    Sum 'Proof size for tensor IOP' lines (PCS opening accounting).

    Non-ZK prints one line; ZK masked+mask openings print two — sum both
    rather than taking the last line times two.

    Do not use ORION_NIZK_PROOF_BYTES: that is the on-disk NIZK blob
    (columns + sparse Merkle paths etc.) and is not the historical
    Input Proof Size.
    """
    total = 0
    found = False
    for line in stdout.splitlines():
        if "Proof size for tensor IOP" not in line:
            continue
        try:
            total += int(line.split()[-2])
            found = True
        except (ValueError, IndexError):
            pass
    return total if found else None

def vole_usage_from_commit(com) -> tuple:
    """
    Read consumed VOLE count and canonical byte size from a commit object.

    Returns (count, bytes). Missing/unsupported objects yield (0, 0).
    """
    if com is None or not hasattr(com, "used_vole_stats"):
        return 0, 0
    try:
        count, nbytes = com.used_vole_stats()
        return int(count), int(nbytes)
    except Exception:
        return 0, 0


def format_vole_usage_metrics(com, party: str):
    """
    Return printable (name, value, unit) triples for VOLE usage.

    party is 'Prover' or 'Verifier'.
    """
    count, nbytes = vole_usage_from_commit(com)
    return [
        ("VOLE Relations Used (%s)" % party, f"{count:,}", ""),
        ("VOLE Relations Bytes (%s)" % party, f"{nbytes:,}", "bytes"),
    ]


def read_orion_result_file(path: str, stdout: str = "") -> OrionOpenResult:
    with open(path, "r") as fh:
        data = json.load(fh)
    value = None
    if data.get("value") is not None:
        value = Fp2.deserialize(data["value"], BASE_PRIME_61)
    # Opening value from JSON; verify timing always from Orion stdout (legacy).
    verification_time = parse_orion_verification_time(stdout)
    return OrionOpenResult(
        ok=bool(data.get("ok")),
        value=value,
        verification_time=verification_time,
    )


def generate_shared_random_input_file(
    path: str,
    n_copies: int,
    values_per_copy: int = 384,
    value_max: int = 255,
):
    """Generate one shared private input snapshot for GKR and Orion."""
    lines = []
    for _ in range(n_copies):
        row = [str(secrets.randbelow(value_max + 1)) for _ in range(values_per_copy)]
        lines.append(" ".join(row))
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
        fh.write("\n")
    return path


def infer_macroblock_grid(n_copies: int, mb_width: Optional[int] = None):
    """
    Infer (W_blocks, H_blocks) with W_blocks * H_blocks == n_copies.

    Matches VideoEdition row-major macroblock order: index = y * W + x.
    If mb_width is unset, pick the landscape-ish factorisation closest to
    4:3 or 16:9 (same convention used by 720x480 -> 45x30 for C=1350).
    """
    n_copies = int(n_copies)
    if n_copies <= 0:
        raise ValueError("n_copies must be positive")
    if mb_width is not None:
        w = int(mb_width)
        if w <= 0 or n_copies % w != 0:
            raise ValueError(
                "mb_width=%s does not divide n_copies=%s" % (mb_width, n_copies)
            )
        return w, n_copies // w

    best = None
    best_score = None
    for w in range(1, n_copies + 1):
        if n_copies % w != 0:
            continue
        h = n_copies // w
        ar = w / float(h)
        score = min(abs(ar - 4.0 / 3.0), abs(ar - 16.0 / 9.0), abs(ar - 1.5))
        if w < h:
            score += 0.5
        if best is None or score < best_score or (
            abs(score - best_score) < 1e-12 and w > best[0]
        ):
            best = (w, h)
            best_score = score
    assert best is not None
    return best


def build_crop_bit_mask(
    n_copies: int,
    x_start: float,
    x_end: float,
    y_start: float,
    y_end: float,
    mb_width: Optional[int] = None,
):
    """
    0/1 crop flags per macroblock, same indexing as VideoEdition.Crop.crop.
    Coordinates are relative [0,1] windows: kept region is [x_start,x_end) x
    [y_start,y_end) in macroblock units after int() truncation.
    """
    for name, val in (
        ("x_start", x_start),
        ("x_end", x_end),
        ("y_start", y_start),
        ("y_end", y_end),
    ):
        if not (0.0 <= float(val) <= 1.0):
            raise ValueError("%s=%s out of [0,1]" % (name, val))
    if float(x_end) <= float(x_start) or float(y_end) <= float(y_start):
        raise ValueError("crop window must satisfy x_end>x_start and y_end>y_start")

    w_blocks, h_blocks = infer_macroblock_grid(n_copies, mb_width)
    xs = int(float(x_start) * w_blocks)
    xe = int(float(x_end) * w_blocks)
    ys = int(float(y_start) * h_blocks)
    ye = int(float(y_end) * h_blocks)
    bits = [0] * int(n_copies)
    for y in range(ys, ye):
        base = y * w_blocks
        for x in range(xs, xe):
            bits[base + x] = 1
    return bits, w_blocks, h_blocks


def prepare_random_circuit_io(
    pws_path: str,
    n_copies: int,
    input_path: str = "input.txt",
    output_path: str = "output.txt",
    value_max: int = 255,
    crop_region: Optional[Sequence[float]] = None,
    mb_width: Optional[int] = None,
):
    """
    Generate shared random input.txt + matching output.txt for truepix.

    Orion and GKR must see the same private input snapshot. Verifier reads
    output.txt, so we evaluate the PWS circuit once and write the public
    outputs (first 384 wires per copy; circuit pads the rest with zeros).

    For Crop.pws, the last private wire is the per-macroblock keep flag.
    Pass crop_region=(x0,x1,y0,y1) in [0,1] (same as TruePix.sh --crop) to
    set that flag to 0/1 over a rectangle; otherwise Crop defaults to
    (0.2, 0.8, 0.2, 0.8). Pixel channels remain uniform random in [0,value_max].
    """
    import pypws
    from libTruePix.defs import Defs
    from libTruePix.parse_pws import parse_pws
    from libTruePix.arithcircuitbuilder import ArithCircuitBuilder

    raw = pypws.parse_pws(pws_path, str(Defs.prime))
    input_layer, in0vv, in1vv, typvv, muxvv = parse_pws(raw)
    n_priv = sum(1 for x in input_layer if x is None)
    if n_priv <= 0:
        raise ValueError("PWS has no private inputs: %s" % pws_path)

    base = os.path.basename(pws_path).lower()
    is_crop = base.startswith("crop")
    crop_bits = None
    crop_meta = None
    if is_crop:
        if n_priv < 1:
            raise ValueError("Crop.pws expected a crop-bit private wire")
        region = crop_region
        if region is None:
            region = (0.2, 0.8, 0.2, 0.8)
        if len(region) != 4:
            raise ValueError("crop_region must be (x_start, x_end, y_start, y_end)")
        crop_bits, w_blocks, h_blocks = build_crop_bit_mask(
            n_copies, region[0], region[1], region[2], region[3], mb_width
        )
        crop_meta = {
            "crop_region": [float(x) for x in region],
            "mb_width": w_blocks,
            "mb_height": h_blocks,
            "kept_blocks": int(sum(crop_bits)),
        }

    priv_rows = []
    full_rows = []
    for copy_idx in range(n_copies):
        if is_crop:
            priv = [secrets.randbelow(value_max + 1) for _ in range(n_priv - 1)]
            priv.append(int(crop_bits[copy_idx]))
        else:
            priv = [secrets.randbelow(value_max + 1) for _ in range(n_priv)]
        priv_rows.append(priv)
        full = []
        vidx = 0
        for wire in input_layer:
            if wire is None:
                full.append(priv[vidx])
                vidx += 1
            else:
                full.append(int(wire) % Defs.prime)
        full_rows.append(full)

    builder = ArithCircuitBuilder(
        n_copies, len(input_layer), in0vv, in1vv, typvv, muxvv
    )
    ckt_outputs, _ = builder.run(full_rows)

    with open(input_path, "w") as fh:
        for row in priv_rows:
            fh.write(" ".join(str(v) for v in row) + "\n")

    # Match VideoEdition / process_file_to_arrays convention: 384 public outs.
    with open(output_path, "w") as fh:
        for outs in ckt_outputs:
            # Circuit layer is padded to 512; public file keeps first 384.
            pub = list(outs[:384])
            fh.write(" ".join(str(int(v) % Defs.prime) for v in pub) + "\n")

    out = {
        "input_path": input_path,
        "output_path": output_path,
        "n_copies": n_copies,
        "n_priv": n_priv,
        "pws": pws_path,
    }
    if crop_meta is not None:
        out.update(crop_meta)
    return out


def write_input_manifest(
    path: str,
    n_copies: int,
    copy_size: int = 384,
    padded_copy_size: int = 512,
):
    import math

    padded_copies = 1 << math.ceil(math.log2(max(1, n_copies)))
    payload = {
        "protocol": PROTOCOL_ID,
        "layout": LAYOUT_ID,
        "copies": n_copies,
        "copy_size": copy_size,
        "padded_copy_size": padded_copy_size,
        "padded_copies": padded_copies,
        "total_elements": padded_copies * padded_copy_size,
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    return payload


def read_commit_manifest(path: Optional[str] = None) -> dict:
    """
    Load the Orion commitment manifest written by linearPC_multi_commit_zk.

    Raises if the file is missing or does not describe this protocol/layout: the
    Fiat-Shamir challenge point is bound to these fields, so a malformed or
    absent manifest must not be silently tolerated.
    """
    if path is None:
        path = os.environ.get("TRUEPIX_ORION_COMMIT_FILE", ORION_COMMIT_FILE)
    if not os.path.isfile(path):
        raise IOError(
            "missing Orion commitment manifest %s; run the commit phase "
            "(run_truepix_signer.py) before proving" % path
        )
    with open(path, "r") as fh:
        manifest = json.load(fh)

    if manifest.get("protocol") not in _PROTOCOL_ALIASES:
        raise ValueError(
            "commitment manifest %s has protocol %r, expected one of %r"
            % (path, manifest.get("protocol"), sorted(_PROTOCOL_ALIASES))
        )
    if manifest.get("layout") != LAYOUT_ID:
        raise ValueError(
            "commitment manifest %s has layout %r, expected %r"
            % (path, manifest.get("layout"), LAYOUT_ID)
        )
    for field in _MANIFEST_INT_FIELDS:
        if field not in manifest:
            raise ValueError("commitment manifest %s is missing %r" % (path, field))
        manifest[field] = int(manifest[field])

    zk = manifest.get("zk", True)
    if isinstance(zk, str):
        zk = zk.strip().lower() in ("1", "true", "yes")
    manifest["zk"] = bool(zk)

    masked = manifest.get("masked_root")
    if not isinstance(masked, str) or len(masked) != 64:
        raise ValueError("commitment manifest %s has a bad masked_root" % path)
    int(masked, 16)

    mask = manifest.get("mask_root", "")
    if manifest["zk"]:
        if not isinstance(mask, str) or len(mask) != 64:
            raise ValueError("commitment manifest %s has a bad mask_root" % path)
        int(mask, 16)
    else:
        if mask is None:
            mask = ""
        if not isinstance(mask, str):
            raise ValueError("commitment manifest %s has a bad mask_root" % path)
        if mask:
            if len(mask) != 64:
                raise ValueError("commitment manifest %s has a bad mask_root" % path)
            int(mask, 16)
    manifest["mask_root"] = mask
    return manifest


def commit_binding(manifest: dict) -> list:
    """
    Canonical Fiat-Shamir absorption of the Orion commitment.

    Absorbing this before the GKR challenges are drawn is what stops a prover
    from picking its private input after seeing the challenge point: the
    challenges depend on the Merkle roots, and the open phase refuses to run
    against data whose roots differ from these.
    """
    return [
        "orion-commit",
        PROTOCOL_ID,
        LAYOUT_ID,
        1 if manifest.get("zk", True) else 0,
    ] + [int(manifest[field]) for field in _MANIFEST_INT_FIELDS] + [
        manifest["masked_root"],
        manifest.get("mask_root") or "",
    ]


def check_manifest_layout(
    manifest: dict,
    n_copies: int,
    copy_size: int,
    const_idx: int,
    const_val: int,
):
    """Ensure the commitment was made over the packing this circuit uses."""
    expected = {
        "copies": int(n_copies),
        "copy_size": int(copy_size),
        "const_idx": int(const_idx),
        "const_val": int(const_val),
    }
    mismatches = [
        "%s: manifest=%d circuit=%d" % (key, manifest[key], want)
        for key, want in expected.items()
        if manifest[key] != want
    ]
    if mismatches:
        raise ValueError(
            "Orion commitment was made over a different input packing (%s)"
            % "; ".join(mismatches)
        )


def infer_gkr_input_layout(pws_path: Optional[str] = None, input_path: str = "input.txt"):
    """
    Infer Orion/GKR private-input packing for a PWS op.

    Returns (copy_size, const_idx, const_val). const_idx < 0 means no constant wire.
    """
    copy_size = 384
    const_idx = 384
    const_val = 128
    if pws_path:
        base = os.path.basename(pws_path).lower()
        if base.startswith("inv"):
            const_val = 255
        elif base.startswith("mask"):
            const_idx = -1
            const_val = 0
        elif base.startswith("crop"):
            # Crop.pws lists V385=128, but pypws optimize drops it (unused).
            # File lines are 385 public vars; pad the rest with zeros.
            copy_size = 385
            const_idx = -1
            const_val = 0
        elif base.startswith("bright"):
            # bright.pws typically mirrors gray-style packing; keep defaults
            pass
    if os.path.isfile(input_path):
        with open(input_path, "r") as fh:
            line = fh.readline().strip()
        if line:
            copy_size = len(line.split())
    return copy_size, const_idx, const_val


def run_orion_open_with_point(
    n_copies: int,
    userandom: int,
    point_file: str,
    result_file: str,
    binary: Optional[str] = None,
    use_zk: bool = True,
    copy_size: int = 384,
    const_idx: int = 384,
    const_val: int = 128,
) -> OrionOpenResult:
    """
    Invoke Orion open binary with GKR point file.

    The C++ binary is expected to read gkr_point.json when present.
    Legacy random-point generation remains in the binary but is skipped when
    the point file exists.

    truepix always requires shared input.txt (userandom forced to 0).
    """
    if binary is None:
        binary = orion_binary("open", use_zk)
    # Shared snapshot is mandatory under truepix.
    userandom = 0

    # A result file left over from an earlier run must not be mistaken for
    # this run's output.
    if os.path.isfile(result_file):
        os.remove(result_file)

    env = orion_env(copy_size, const_idx, const_val)
    env["TRUEPIX_GKR_POINT_FILE"] = os.path.abspath(point_file)
    env["TRUEPIX_ORION_RESULT_FILE"] = os.path.abspath(result_file)

    # Pin to one CPU like legacy run_truepix_verifier for comparable timing.
    cmd = cpu_pin() + [binary, str(n_copies), str(userandom)]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )

    verification_time = parse_orion_verification_time(proc.stdout)

    if not os.path.isfile(result_file):
        return OrionOpenResult(
            ok=False,
            value=None,
            raw_stdout=proc.stdout + proc.stderr,
            verification_time=verification_time,
        )

    result = read_orion_result_file(result_file, stdout=proc.stdout)
    result.raw_stdout = proc.stdout + proc.stderr
    # The binary reports commitment-root and opening failures through its exit
    # status as well as the result file; require both to agree.
    result.ok = bool(result.ok) and proc.returncode == 0
    return result


def cpu_pin() -> List[str]:
    """Prefix that pins a child to one core.

    TRUEPIX_CPU selects the core. The default is 1, matching the legacy
    single-thread timing runs. Multi-thread random mode sets one core per worker.
    """
    cpu = os.environ.get("TRUEPIX_CPU", "1")
    return ["taskset", "-c", str(cpu)]


def orion_binary(phase: str, use_zk: bool) -> str:
    """
    Map a TruePix proof mode to the matching Orion executable.

    phase is 'commit', 'prove' or 'open'. ZK TruePix uses the *_zk binaries
    built from Orion_zk; non-ZK TruePix uses the unsuffixed binaries built
    from Orion_nonzk. That is six executables in total.
    """
    if phase not in ("commit", "prove", "open"):
        raise ValueError("unknown Orion phase %r" % phase)
    if use_zk:
        return "./linearPC_multi_%s_zk" % phase
    return "./linearPC_multi_%s" % phase


def orion_mode(base_env: Optional[dict] = None) -> str:
    """Return TRUEPIX_ORION_MODE: nizk (default) or interactive."""
    env = os.environ if base_env is None else base_env
    m = str(env.get("TRUEPIX_ORION_MODE", "nizk")).strip().lower()
    if m in ("interactive", "interact"):
        return "interactive"
    return "nizk"


def orion_single_core_env(base_env: Optional[dict] = None) -> dict:
    """
    OpenMP defaults to one worker per core. Each worker keeps a large stack
    (~8MiB) that shows up in peak RSS. Force one thread so the Orion process
    stays single-threaded.
    """
    env = dict(os.environ if base_env is None else base_env)
    env["OMP_NUM_THREADS"] = "1"
    return env


def orion_env(
    copy_size: int = 384,
    const_idx: int = 384,
    const_val: int = 128,
    base_env: Optional[dict] = None,
) -> dict:
    """Environment shared by the Orion commit, prove and open binaries."""
    env = orion_single_core_env(base_env)
    env["TRUEPIX_PROTOCOL"] = PROTOCOL_ID
    env["TRUEPIX_COPY_SIZE"] = str(copy_size)
    env["TRUEPIX_CONST_IDX"] = str(const_idx)
    env["TRUEPIX_CONST_VAL"] = str(const_val)
    env["TRUEPIX_ORION_COMMIT_FILE"] = os.path.abspath(
        os.environ.get("TRUEPIX_ORION_COMMIT_FILE", ORION_COMMIT_FILE)
    )
    env["TRUEPIX_MASK_SEED_FILE"] = os.path.abspath(
        os.environ.get("TRUEPIX_MASK_SEED_FILE", ORION_MASK_SEED_FILE)
    )
    mode = orion_mode(env)
    env["TRUEPIX_ORION_MODE"] = mode
    if mode == "nizk":
        env.setdefault(
            "TRUEPIX_ORION_PROOF_FILE",
            os.path.abspath(os.environ.get("TRUEPIX_ORION_PROOF_FILE", ORION_PROOF_FILE)),
        )
    return env
