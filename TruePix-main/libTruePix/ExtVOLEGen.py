#!/usr/bin/python3
"""
Extension-field VOLE relation generator for protocol truepix.

Generates Delta, U, V, P in Fp2 with P = U*Delta + V.
Stores coordinates in compact array('Q') buffers (not Python Fp2 objects)
to keep generation peak RSS close to the legacy VOLE path.

Legacy VOLEGen.py is left unchanged.
"""

from __future__ import annotations

import secrets
import struct
from array import array
from typing import List, Optional, Tuple

from libTruePix.extfield import BASE_PRIME_61, Fp2

# SD circuits here consume about 100 correlations. 500 leaves headroom
# without writing the old 100000-instance JSON pool every run.
DEFAULT_VOLE_INSTANCES = 500

_MAGIC = b"EVOL"
_VERSION = 1
_ROLE_PROVER = 1
_ROLE_VERIFIER = 2
_HEADER = struct.Struct("<4sIIIIQ")


def _rand_nonzero(p: int) -> Tuple[int, int]:
    while True:
        real = secrets.randbelow(p)
        imag = secrets.randbelow(p)
        if real or imag:
            return real, imag


def _write_array(fh, values: array) -> None:
    fh.write(values.tobytes())


def _read_array(fh, n: int) -> array:
    raw = fh.read(n * 8)
    if len(raw) != n * 8:
        raise ValueError("truncated VOLE file")
    out = array("Q")
    out.frombytes(raw)
    return out


class ExtVOLEGenerator:
    FIELD_ID = "fp2-mersenne61"
    PROTOCOL = "truepix"

    def __init__(self, base_prime: int = BASE_PRIME_61, security_repetitions: int = 1):
        self.base_prime = int(base_prime)
        self.security_repetitions = max(1, int(security_repetitions))
        self.deltas: List[Fp2] = []
        # Compact coordinate buffers: list over security repetitions.
        self.u_re: List[array] = []
        self.u_im: List[array] = []
        self.v_re: List[array] = []
        self.v_im: List[array] = []
        self.p_re: List[array] = []
        self.p_im: List[array] = []
        # Legacy-compatible aliases (populated only if callers ask).
        self.u_lists: Optional[List] = None
        self.v_lists: Optional[List] = None
        self.p_lists: Optional[List] = None

    def generate_deltas(self) -> List[Fp2]:
        self.deltas = [
            Fp2.random(self.base_prime, nonzero=True)
            for _ in range(self.security_repetitions)
        ]
        return list(self.deltas)

    def generate_vole_instances(self, num_instances: int):
        if not self.deltas:
            raise ValueError("Call generate_deltas() first")

        num_instances = int(num_instances)
        self.u_re, self.u_im = [], []
        self.v_re, self.v_im = [], []
        self.p_re, self.p_im = [], []
        self.u_lists = self.v_lists = self.p_lists = None

        p = self.base_prime
        for delta in self.deltas:
            dr, di = delta.real, delta.imag
            ur = array("Q", [0]) * num_instances
            ui = array("Q", [0]) * num_instances
            vr = array("Q", [0]) * num_instances
            vi = array("Q", [0]) * num_instances
            pr = array("Q", [0]) * num_instances
            pi = array("Q", [0]) * num_instances
            for i in range(num_instances):
                ure, uim = _rand_nonzero(p)
                vre, vim = _rand_nonzero(p)
                # p = u*delta + v
                # (ur+ui*i)(dr+di*i) = (ur*dr - ui*di) + (ur*di + ui*dr)*i
                t0 = (ure * dr - uim * di) % p
                t1 = (ure * di + uim * dr) % p
                ur[i] = ure
                ui[i] = uim
                vr[i] = vre
                vi[i] = vim
                pr[i] = (t0 + vre) % p
                pi[i] = (t1 + vim) % p
            self.u_re.append(ur)
            self.u_im.append(ui)
            self.v_re.append(vr)
            self.v_im.append(vi)
            self.p_re.append(pr)
            self.p_im.append(pi)

        # Keep return shape loosely compatible; avoid materializing Fp2 lists.
        return (len(self.u_re), num_instances)

    def clear(self):
        """Drop all large buffers so peak RSS can be reclaimed before prove."""
        self.u_re = self.u_im = []
        self.v_re = self.v_im = []
        self.p_re = self.p_im = []
        self.u_lists = self.v_lists = self.p_lists = None
        self.deltas = []

    def save_to_files(self, prover_file: str, verifier_file: str, session_id: str = ""):
        if not self.deltas or not self.u_re:
            raise ValueError("No VOLE instances generated yet")
        del session_id  # binary header has no session string
        n = len(self.u_re[0])
        reps = self.security_repetitions
        with open(prover_file, "wb") as fh:
            fh.write(_HEADER.pack(_MAGIC, _VERSION, _ROLE_PROVER, reps, n, self.base_prime))
            for re, im in zip(self.u_re, self.u_im):
                _write_array(fh, re)
                _write_array(fh, im)
            for re, im in zip(self.v_re, self.v_im):
                _write_array(fh, re)
                _write_array(fh, im)
        with open(verifier_file, "wb") as fh:
            fh.write(_HEADER.pack(_MAGIC, _VERSION, _ROLE_VERIFIER, reps, n, self.base_prime))
            deltas = array("Q")
            for d in self.deltas:
                deltas.append(d.real)
                deltas.append(d.imag)
            _write_array(fh, deltas)
            for re, im in zip(self.p_re, self.p_im):
                _write_array(fh, re)
                _write_array(fh, im)


def read_vole_file(filename: str):
    """Load a binary VOLE file. Returns None when the file is legacy JSON."""
    with open(filename, "rb") as fh:
        prefix = fh.read(4)
        if prefix != _MAGIC:
            return None
        rest = fh.read(_HEADER.size - 4)
        if len(rest) != _HEADER.size - 4:
            raise ValueError("truncated VOLE header")
        _magic, version, role, reps, n, base_prime = _HEADER.unpack(prefix + rest)
        if version != _VERSION:
            raise ValueError("unsupported VOLE file version %s" % version)
        deltas = []
        streams = []
        if role == _ROLE_VERIFIER:
            raw = _read_array(fh, reps * 2)
            deltas = [(raw[2 * i], raw[2 * i + 1]) for i in range(reps)]
            nstreams = 1
        elif role == _ROLE_PROVER:
            nstreams = 2
        else:
            raise ValueError("unknown VOLE role %s" % role)
        for _ in range(reps * nstreams):
            streams.append((_read_array(fh, n), _read_array(fh, n)))
    return {
        "role": role,
        "security_repetitions": reps,
        "n": n,
        "base_prime": base_prime,
        "deltas": deltas,
        "streams": streams,
    }
