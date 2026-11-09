#!/usr/bin/env python3
"""
Resident multi-thread worker for TruePix.sh.

Pipeline per round (keeps TOTAL Prove Time lower under many workers):
  1) Commit window: even thread ids sign first; odd ids wait, then sign.
  2) Barrier: every worker has signed before anyone proves.
  3) Prove window: at most K workers prove at once (TRUEPIX_PROVE_SLOTS / --prove-slots).
  4) Barrier: every worker has proved before anyone verifies (--verify-barrier),
     so no verify overlaps another worker's prove.
  5) Verify.

Optional warm-up rounds (--warmup) run the same pipeline first; their
metrics come before the TRUEPIX_MEASURE_BEGIN marker and are not summed.
"""

from __future__ import annotations

import argparse
import fcntl
import glob
import os
import sys
import time
from typing import IO, Optional


def _clean_round_artifacts(reuse_io: bool) -> None:
    patterns = [
        "hyraxproof",
        "orion_commit.json",
        "orion_mask_seed.txt",
        "signature.bin",
        "public_key.pem",
        "gkr_point.json",
        "gkr_point.txt",
        "gkr_point_prover.json",
        "gkr_point_prover.txt",
        "orion_open_result.json",
        "orion_open_result_e2e.json",
        "vole_prover_*.json",
        "vole_verifier_*.json",
        "vole_ext_prover_*.json",
        "vole_ext_verifier_*.json",
    ]
    if not reuse_io:
        patterns = ["input.txt", "output.txt"] + patterns
    for pat in patterns:
        if "*" in pat:
            for path in glob.glob(pat):
                try:
                    os.remove(path)
                except OSError:
                    pass
        else:
            try:
                os.remove(pat)
            except OSError:
                pass


def _group_a_count(threads: int) -> int:
    return (threads + 1) // 2


def _round_dir(barrier: str, round_idx: int) -> str:
    path = os.path.join(barrier, "r%d" % round_idx)
    os.makedirs(path, exist_ok=True)
    return path


def _count_numeric_marks(round_dir: str, prefix: str) -> int:
    """Count files named ``{prefix}_{int}`` (does not match ``{prefix}_A_*``)."""
    n = 0
    for path in glob.glob(os.path.join(round_dir, prefix + "_*")):
        suffix = os.path.basename(path)[len(prefix) + 1 :]
        if suffix.isdigit():
            n += 1
    return n


def _wait_numeric_marks(
    round_dir: str, prefix: str, expect: int, timeout_s: float, label: str
) -> None:
    if expect <= 0:
        return
    deadline = time.time() + timeout_s
    while True:
        n = _count_numeric_marks(round_dir, prefix)
        if n >= expect:
            return
        failed = glob.glob(os.path.join(round_dir, "failed_*"))
        if failed:
            raise RuntimeError(
                "aborting %s: another worker failed (%s)"
                % (label, ", ".join(sorted(os.path.basename(p) for p in failed)))
            )
        if time.time() > deadline:
            raise TimeoutError(
                "timed out waiting for %s (have %d / %d) in %s"
                % (label, n, expect, round_dir)
            )
        time.sleep(0.01)


def _mark(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("1\n")


def _default_prove_slots(threads: int) -> int:
    env = os.environ.get("TRUEPIX_PROVE_SLOTS", "").strip()
    if env:
        return max(1, min(threads, int(env)))
    # Cap concurrent proves so Orion/GKR do not all thrash memory at once.
    return max(1, min(threads, 4))


class ProveSlotPool:
    """Exclusive flock slots under barrier/prove_slots/slot_*.lock."""

    def __init__(self, barrier: str, slots: int):
        self.slots = max(1, int(slots))
        self.dir = os.path.join(barrier, "prove_slots")
        os.makedirs(self.dir, exist_ok=True)
        self._paths = []
        for i in range(self.slots):
            path = os.path.join(self.dir, "slot_%d.lock" % i)
            if not os.path.exists(path):
                with open(path, "ab"):
                    pass
            self._paths.append(path)

    def acquire(self, timeout_s: float) -> IO[bytes]:
        deadline = time.time() + timeout_s
        while True:
            for path in self._paths:
                fh = open(path, "rb+")
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return fh
                except BlockingIOError:
                    fh.close()
            if time.time() > deadline:
                raise TimeoutError(
                    "timed out waiting for a prove slot (%d slots)" % self.slots
                )
            time.sleep(0.01)

    @staticmethod
    def release(fh: Optional[IO[bytes]]) -> None:
        if fh is None:
            return
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()


def _call_with_argv(fn, argv) -> int:
    old = sys.argv
    try:
        sys.argv = argv
        ret = fn()
        if ret is None:
            return 0
        return int(ret)
    finally:
        sys.argv = old


def main() -> int:
    ap = argparse.ArgumentParser(description="Resident TruePix multi-thread worker")
    ap.add_argument("--runs", type=int, required=True)
    ap.add_argument("--thread-id", type=int, required=True)
    ap.add_argument("--threads", type=int, required=True)
    ap.add_argument("--barrier", required=True)
    ap.add_argument("--pws", required=True)
    ap.add_argument("-c", "--constraint", type=int, required=True)
    ap.add_argument("-z", "--zk", type=int, required=True, choices=(0, 1))
    ap.add_argument(
        "--reuse-io",
        action="store_true",
        help="Use input.txt/output.txt already linked into the worker dir",
    )
    ap.add_argument(
        "--video",
        action="store_true",
        help="Deprecated alias for --reuse-io",
    )
    ap.add_argument(
        "--prove-slots",
        type=int,
        default=0,
        help="Max concurrent proves (0 => TRUEPIX_PROVE_SLOTS or min(threads,4))",
    )
    ap.add_argument(
        "--warmup",
        type=int,
        default=0,
        help="Extra leading rounds whose metrics are excluded from the sums",
    )
    ap.add_argument(
        "--verify-barrier",
        type=int,
        default=1,
        choices=(0, 1),
        help="1 => wait until every worker has proved before verifying",
    )
    ap.add_argument(
        "--commit-timeout",
        type=float,
        default=3600.0,
        help="seconds to wait for commit / all-signed barriers",
    )
    ap.add_argument(
        "--prove-timeout",
        type=float,
        default=7200.0,
        help="seconds to wait for a prove slot",
    )
    args = ap.parse_args()

    if args.runs <= 0 or args.threads <= 0:
        print("ERROR: --runs and --threads must be positive", file=sys.stderr)
        return 1
    if args.thread_id < 0 or args.thread_id >= args.threads:
        print("ERROR: --thread-id out of range", file=sys.stderr)
        return 1

    import run_truepix_signer as signer
    import run_truepix_prover as prover
    import run_truepix_verifier as verifier
    from libTruePix.defs import Defs
    from libTruePix.fp2_link import prepare_random_circuit_io
    from libTruePix import native_fp2_bridge as nfb

    if nfb.GPU_ACTIVE:
        print("Worker GKR backend: GPU", flush=True)
    else:
        print("Worker GKR backend: CPU (%s)" % (nfb.GPU_FAIL_REASON or "n/a"), flush=True)

    reuse_io = bool(args.reuse_io or args.video)
    use_zk = int(args.zk)
    z_flag = "1" if use_zk == 1 else "2"
    pws = args.pws
    constraint = int(args.constraint)
    tid = int(args.thread_id)
    threads = int(args.threads)
    in_group_a = (tid % 2) == 0
    expect_a = _group_a_count(threads)
    prove_slots = (
        max(1, min(threads, int(args.prove_slots)))
        if args.prove_slots > 0
        else _default_prove_slots(threads)
    )
    os.makedirs(args.barrier, exist_ok=True)
    slot_pool = ProveSlotPool(args.barrier, prove_slots)

    if tid == 0:
        print(
            "Pipeline: commit-stagger -> all-signed barrier -> prove-slots=%d -> verify"
            % prove_slots
        )

    if reuse_io:
        if not os.path.isfile("input.txt") or not os.path.isfile("output.txt"):
            print(
                "ERROR: --reuse-io requires input.txt and output.txt in the worker directory",
                file=sys.stderr,
            )
            return 1

    warmup = max(0, int(args.warmup))
    total_rounds = warmup + args.runs
    cpu_label = os.environ.get("TRUEPIX_CPU", "?")
    for r in range(1, total_rounds + 1):
        if r == warmup + 1:
            print("TRUEPIX_MEASURE_BEGIN", flush=True)
        if r <= warmup:
            print("=== cpu %s warmup %d/%d ===" % (cpu_label, r, warmup))
        else:
            print("=== cpu %s run %d/%d ===" % (cpu_label, r - warmup, args.runs))
        _clean_round_artifacts(reuse_io)
        rdir = _round_dir(args.barrier, r)

        if not reuse_io:
            Defs.configure()
            info = prepare_random_circuit_io(pws, constraint)
            print("Prepared random IO:", info)

        # --- phase 1: commit window ---
        if not in_group_a:
            _wait_numeric_marks(
                rdir, "commitA", expect_a, args.commit_timeout, "group-A commit"
            )

        print("=== Running TruePix Signer ===")
        try:
            signer.run_truepix(constraint, use_zk, pws)
        except Exception:
            _mark(os.path.join(rdir, "failed_%d" % tid))
            raise
        if in_group_a:
            _mark(os.path.join(rdir, "commitA_%d" % tid))
        _mark(os.path.join(rdir, "signed_%d" % tid))
        print("Signed; waiting for all %d workers before prove" % threads)

        # --- phase 2: everyone signed ---
        _wait_numeric_marks(
            rdir, "signed", threads, args.commit_timeout, "all-signed barrier"
        )

        # --- phase 3: limited concurrent prove ---
        print("=== Running TruePix Prover (waiting for prove slot) ===")
        slot_fh = None
        try:
            slot_fh = slot_pool.acquire(args.prove_timeout)
            print("=== Running TruePix Prover (slot acquired) ===")
            prover_argv = [
                "run_truepix_prover.py",
                "-p", pws,
                "-c=%d" % constraint,
                "-z", z_flag,
                "-o", "hyraxproof",
                "-i", "input.txt",
            ]
            if _call_with_argv(prover.main, prover_argv) != 0:
                print("ERROR: prover failed on run %d" % r, file=sys.stderr)
                _mark(os.path.join(rdir, "failed_%d" % tid))
                return 1
        except Exception:
            _mark(os.path.join(rdir, "failed_%d" % tid))
            raise
        finally:
            ProveSlotPool.release(slot_fh)

        if args.verify_barrier:
            _mark(os.path.join(rdir, "proved_%d" % tid))
            _wait_numeric_marks(
                rdir, "proved", threads, args.prove_timeout, "all-proved barrier"
            )

        print("=== Running TruePix Verifier ===")
        verifier_argv = [
            "run_truepix_verifier.py",
            "-p", pws,
            "-c=%d" % constraint,
            "-z", z_flag,
            "-v", "hyraxproof",
            "-i", "input.txt",
        ]
        if _call_with_argv(verifier.main, verifier_argv) != 0:
            print("ERROR: verifier failed on run %d" % r, file=sys.stderr)
            _mark(os.path.join(rdir, "failed_%d" % tid))
            return 1

        _mark(os.path.join(rdir, "done_%d" % tid))
        print("All TruePix proof processes completed successfully")

    return 0


if __name__ == "__main__":
    sys.exit(main())
