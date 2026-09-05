#!/usr/bin/env python3
"""Reproduce synthetic SPEC-077 TEST-001 vectors, using only Python stdlib.

Run from the repo root: python3 tests/support/handoff_vectors.py
No production secrets or network inputs are used.
"""
import base64
import hashlib
import json


def head(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    for size, additional in [(1, 24), (2, 25), (4, 26), (8, 27)]:
        if value < 1 << (size * 8):
            return bytes([major << 5 | additional]) + value.to_bytes(size, "big")
    raise ValueError("u64 overflow")


def cbor(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(cbor, value))
    entries = sorted((cbor(k), cbor(v)) for k, v in value.items())
    return head(5, len(entries)) + b"".join(k + v for k, v in entries)


def vector(maximal):
    c = bytes(range(16))
    t = bytes(range(240, 256))
    mailbox = bytes(range(32))
    commitment = hashlib.sha256(b"cbcl-pairing claim-v2 commitment\0" + mailbox + t).digest()
    carrier = {
        "version": 2,
        "profile": "anuna.io/credential/v2",
        "profile-version": 2,
        "application-context": "https://a.b/" + "x" * (2036 if maximal else 1),
        "relay-origin": "https://" + "r" * (264 if maximal else 1),
        "locator": mailbox,
        "carrier-ceremony-id": bytes([0x23]) * 32,
        "carrier-nonce": bytes([0x45]) * 32,
        "claim-commitment": commitment,
        "relay-expires-at": (1 << 64) - 1 if maximal else 1800000900,
    }
    if maximal:
        carrier["expected-allocator-key"] = bytes([0x67]) * 32
    public = cbor(carrier)
    decoded = cbor(["selfsame-pairing-handoff/v1", public, c, t])
    text = "SSPAIR1:" + base64.urlsafe_b64encode(decoded).decode().rstrip("=")
    if maximal:
        assert (len(public), len(decoded), len(text)) == (2695, 2762, 3691)
    return {
        "name": "maximum" if maximal else "small",
        "carrier_hex": public.hex(),
        "carrier_sha256": hashlib.sha256(public).hexdigest(),
        "c_hex": c.hex(),
        "t_hex": t.hex(),
        "decoded_hex": decoded.hex(),
        "handoff": text,
    }


if __name__ == "__main__":
    print(json.dumps([vector(False), vector(True)], indent=2))
