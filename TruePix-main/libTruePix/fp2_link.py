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
    if data.get("protocol") != PROTOCOL_ID:
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
    Sum all 'Open time' lines from Orion prove/open (Input Prove Time).

    Non-ZK prints one line; ZK masked+mask openings print two, and Input Prove
    Time should count both. Streaming re-encode is reported separately as
    'Encode preprocess time' and is already excluded from Open time.
    """
    total = 0.0
    found = False
    for line in stdout.splitlines():
        if "Open time" not in line:
            continue
        try:
            total += float(line.split()[-1])
            found = True
        except ValueError:
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


def prepare_random_circuit_io(
    pws_path: str,
    n_copies: int,
    input_path: str = "input.txt",
    output_path: str = "output.txt",
    value_max: int = 255,
):
    """
    Generate shared random input.txt + matching output.txt for truepix.

    Orion and GKR must see the same private input snapshot. Verifier reads
    output.txt, so we evaluate the PWS circuit once and write the public
    outputs (first 384 wires per copy; circuit pads the rest with zeros).
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

    priv_rows = []
    full_rows = []
    for _ in range(n_copies):
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

    return {
        "input_path": input_path,
        "output_path": output_path,
        "n_copies": n_copies,
        "n_priv": n_priv,
        "pws": pws_path,
    }


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

    if manifest.get("protocol") != PROTOCOL_ID:
        raise ValueError(
            "commitment manifest %s has protocol %r, expected %r"
            % (path, manifest.get("protocol"), PROTOCOL_ID)
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
    cmd = ["taskset", "-c", "1", binary, str(n_copies), str(userandom)]
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


def orion_env(
    copy_size: int = 384,
    const_idx: int = 384,
    const_val: int = 128,
    base_env: Optional[dict] = None,
) -> dict:
    """Environment shared by the Orion commit, prove and open binaries."""
    env = dict(os.environ if base_env is None else base_env)
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
    return env
