#!/usr/bin/python3
"""
Signer/verifier agreement on what the ECDSA signature actually covers.

Both sides derive the signed message from the Orion commitment manifest, which
pins the input layout and Merkle root(s). The open phase refuses to run against
data whose roots differ from the manifest, so signing it attests to the exact
private input that was committed.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Tuple

from ecdsa import NIST256p, SigningKey, VerifyingKey

from libTruePix.fp2_link import ORION_COMMIT_FILE

PUBKEY_FILE = "public_key.pem"
SIG_FILE = "signature.bin"
HASHFUNC = hashlib.sha256

_DOMAIN = b"truepix/orion-commit/v1\x00"


def _read(path: str) -> bytes:
    if not os.path.isfile(path):
        raise IOError("cannot build the signed message: %s is missing" % path)
    with open(path, "rb") as fh:
        return fh.read()


def build_message(usezk: int = 1) -> bytes:
    del usezk  # message is independent of ZK vs non-ZK once the manifest exists
    return _DOMAIN + _read(ORION_COMMIT_FILE)


def sign(usezk: int = 1) -> dict:
    """Generate a key pair, sign the message and persist both artifacts."""
    message = build_message(usezk)

    keygen_start = time.time()
    sk = SigningKey.generate(curve=NIST256p, hashfunc=HASHFUNC)  # P-256 + SHA-256
    vk = sk.verifying_key
    keygen_time = time.time() - keygen_start

    sign_start = time.time()
    signature = sk.sign(message, hashfunc=HASHFUNC)
    sign_time = time.time() - sign_start

    with open(PUBKEY_FILE, "wb") as fh:
        fh.write(vk.to_pem())
    with open(SIG_FILE, "wb") as fh:
        fh.write(signature)

    return {
        "keygen_time": keygen_time,
        "sign_time": sign_time,
        "signature_size": len(signature),
        "message_size": len(message),
    }


def verify(usezk: int = 1) -> Tuple[bool, float, str]:
    """
    Re-derive the message and check the stored signature over it.

    Returns (ok, elapsed_seconds, detail).
    """
    start = time.time()
    try:
        message = build_message(usezk)
        public_key = VerifyingKey.from_pem(_read(PUBKEY_FILE), hashfunc=HASHFUNC)
        signature = _read(SIG_FILE)
    except (IOError, ValueError) as exc:
        return False, time.time() - start, str(exc)

    try:
        public_key.verify(signature, message, hashfunc=HASHFUNC)
    except Exception as exc:  # ecdsa raises BadSignatureError and friends
        detail = "%s: %s" % (type(exc).__name__, exc)
        return False, time.time() - start, detail

    return True, time.time() - start, "message_size=%d" % len(message)
