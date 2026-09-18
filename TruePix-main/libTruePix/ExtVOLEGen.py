#!/usr/bin/python3
"""
Extension-field VOLE relation generator for protocol truepix.

Generates Delta, U, V, P in Fp2 with P = U*Delta + V.
Stores coordinates in compact array('Q') buffers (not Python Fp2 objects)
to keep generation peak RSS close to the legacy VOLE path.

Legacy VOLEGen.py is left unchanged.
"""

from __future__ import annotations

from array import array
from typing import List, Optional, Tuple

from libTruePix.extfield import BASE_PRIME_61, Fp2


def _write_coord_streams(fh, streams: List[Tuple[array, array]], indent: str = "  "):
    """Write JSON list-of-streams of [real, imag] pairs without a giant Python tree."""
    fh.write("[\n")
    for si, (re, im) in enumerate(streams):
        n = len(re)
        fh.write(indent + "[")
        for j in range(n):
            if j:
                fh.write(",")
            # Compact single-line pairs keep file size similar to json.dump.
            fh.write(f"[{re[j]},{im[j]}]")
            if (j & 0x3FF) == 0x3FF:
                fh.write("\n" + indent)
        fh.write("]")
        if si + 1 < len(streams):
            fh.write(",")
        fh.write("\n")
    fh.write("]")


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
                u = Fp2.random(p, nonzero=True)
                v = Fp2.random(p, nonzero=True)
                # p = u*delta + v  (inline to avoid a third Fp2 temporary living in a list)
                # (ur+ui*i)(dr+di*i) = (ur*dr - ui*di) + (ur*di + ui*dr)*i
                t0 = (u.real * dr - u.imag * di) % p
                t1 = (u.real * di + u.imag * dr) % p
                ur[i] = u.real
                ui[i] = u.imag
                vr[i] = v.real
                vi[i] = v.imag
                pr[i] = (t0 + v.real) % p
                pi[i] = (t1 + v.imag) % p
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

        # Stream JSON so we never hold a nested [[[r,i],...]] Python tree
        # alongside the compact arrays (that duplication was a major RSS spike).
        with open(prover_file, "w") as fh:
            fh.write("{\n")
            fh.write(f'"protocol":"{self.PROTOCOL}",\n')
            fh.write(f'"field":"{self.FIELD_ID}",\n')
            fh.write(f'"base_prime":{self.base_prime},\n')
            fh.write(f'"security_repetitions":{self.security_repetitions},\n')
            fh.write(f'"session_id":"{session_id}",\n')
            fh.write('"u":')
            _write_coord_streams(fh, list(zip(self.u_re, self.u_im)))
            fh.write(',\n"v":')
            _write_coord_streams(fh, list(zip(self.v_re, self.v_im)))
            fh.write("\n}\n")

        with open(verifier_file, "w") as fh:
            fh.write("{\n")
            fh.write(f'"protocol":"{self.PROTOCOL}",\n')
            fh.write(f'"field":"{self.FIELD_ID}",\n')
            fh.write(f'"base_prime":{self.base_prime},\n')
            fh.write(f'"security_repetitions":{self.security_repetitions},\n')
            fh.write(f'"session_id":"{session_id}",\n')
            fh.write('"delta":[')
            fh.write(",".join(f"[{d.real},{d.imag}]" for d in self.deltas))
            fh.write("],\n")
            fh.write('"p":')
            _write_coord_streams(fh, list(zip(self.p_re, self.p_im)))
            fh.write("\n}\n")
