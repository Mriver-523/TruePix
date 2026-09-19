#!/usr/bin/python
#
# Copyright 2017 Riad S. Wahby and the Hyrax authors
# Copyright 2025-2026 the TruePix authors
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
#
# Signer: Orion commitment + ECDSA over the commitment manifest.

import getopt
import resource
import sys
import subprocess

from libTruePix import attest
from libTruePix.fp2_link import cpu_pin, infer_gkr_input_layout, orion_binary, orion_env


def print_section_header(title):
    print("\n" + "=" * 50)
    print(f"=== {title.center(44)} ===")
    print("=" * 50)


def print_metric(name, value, unit=""):
    print(f"{name:<30}: {value:>15} {unit}")


def run_truepix(constraint_size, usezk, pws_file=None):
    # Commit publishes orion_commit.json (layout + Merkle root(s)).
    # ZK: masked + mask polynomials. Non-ZK: a single polynomial.
    copy_size, const_idx, const_val = infer_gkr_input_layout(pws_file)
    cmd = cpu_pin() + [
        orion_binary("commit", usezk == 1),
        str(constraint_size),
        "0",  # shared input.txt is mandatory
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=orion_env(copy_size, const_idx, const_val),
        check=False,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        print("Error: Orion commit phase failed")
        sys.exit(1)

    orion_commit_time = None
    for line in result.stdout.split('\n'):
        if usezk == 1:
            if "Commit time(mask)" in line:
                orion_commit_time = float(line.split()[-1])
        elif "Commit time" in line:
            orion_commit_time = float(line.split()[-1])
    if orion_commit_time is None:
        print("Error: Orion commit phase did not report a commit time")
        sys.exit(1)

    sig_info = attest.sign(usezk)
    ecdsa_sign_time = sig_info["sign_time"]

    print_metric("Input Commit Size", 32*(usezk+1), "bytes")
    print_metric("Input Commit Time", f"{orion_commit_time:.6f}", "seconds")
    print_metric("Input Signed Message Size", f"{sig_info['message_size']}", "bytes")
    print_metric("Input Signature Size", f"{sig_info['signature_size']}", "bytes")
    print_metric("Input Signing Time", f"{ecdsa_sign_time:.6f}", "seconds")
    print_section_header("signature Performance")
    total_Signing_time = orion_commit_time + ecdsa_sign_time

    print_metric("TOTAL Signing Time", f"{total_Signing_time:.6f}", "seconds")
    print_metric("Max Memory Usage", f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}", "MB")


def print_usage():
    print("Usage: python script.py [options]")
    print("Options:")
    print("  -c <size>        Set the constraint size (default: 1350)")
    print("  -z <usezk>       Use zero-knowledge: 1 to enable, 0 to disable (default: 1)")
    print("  --pws <file>     PWS circuit, used to infer the Orion input packing")
    print("  -h, --help       Show this help message")
    sys.exit(1)


def main():
    constraint_size = 1350
    usezk = 1
    pws_file = None

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hc:u:z:",
            ["help", "constraint=", "userandom=", "zk=", "pws="],
        )
    except getopt.GetoptError:
        print_usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_usage()
        elif opt in ("-c", "--constraint"):
            try:
                constraint_size = int(arg)
            except ValueError:
                print("Error: constraint size must be an integer")
                sys.exit(1)
        elif opt in ("-u", "--userandom"):
            # Shared input.txt is always required; flag kept for CLI compatibility.
            try:
                userandom = int(arg)
                if userandom not in (0, 1):
                    print("Error: userandom must be 0 or 1")
                    sys.exit(1)
            except ValueError:
                print("Error: userandom must be 0 or 1")
                sys.exit(1)
        elif opt in ("-z", "--zk"):
            try:
                usezk = int(arg)
                if usezk not in (0, 1):
                    print("Error: usezk must be 0 or 1")
                    sys.exit(1)
            except ValueError:
                print("Error: usezk must be 0 or 1")
                sys.exit(1)
        elif opt == "--pws":
            pws_file = arg

    if pws_file is None:
        print("Error: --pws <file> is required")
        sys.exit(1)

    run_truepix(constraint_size, usezk, pws_file)


if __name__ == "__main__":
    main()
