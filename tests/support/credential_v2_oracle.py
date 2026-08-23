#!/usr/bin/env python3
"""Independent stdlib/cryptography oracle for SPEC-001 TEST-066."""

import hashlib
import hmac
import json
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def head(major: int, value: int) -> bytes:
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")


def cbor_uint(value: int) -> bytes:
    return head(0, value)


def cbor_bytes(value: bytes) -> bytes:
    return head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return head(3, len(encoded)) + encoded


def cbor_array(values: list[bytes]) -> bytes:
    return head(4, len(values)) + b"".join(values)


def cbor_map(entries: list[tuple[bytes, bytes]]) -> bytes:
    ordered = sorted(entries, key=lambda entry: (len(entry[0]), entry[0]))
    return head(5, len(ordered)) + b"".join(key + value for key, value in ordered)


def leb128(value: int) -> bytes:
    output = bytearray()
    while True:
        octet = value & 0x7F
        value >>= 7
        output.append(octet | (0x80 if value else 0))
        if not value:
            return bytes(output)


def length_value(value: bytes) -> bytes:
    return leb128(len(value)) + value


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha512
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def main() -> None:
    inputs = {key: bytes.fromhex(value) for key, value in json.load(sys.stdin).items()}
    shared = X25519PrivateKey.from_private_bytes(inputs["allocator_scalar"]).exchange(
        X25519PublicKey.from_public_bytes(inputs["claimant_share"])
    )
    isk_input = b"".join(
        length_value(value)
        for value in (
            b"CPace255_ISK",
            inputs["sid"],
            shared,
            inputs["allocator_share"],
            inputs["allocator_ad"],
            inputs["claimant_share"],
            inputs["claimant_ad"],
        )
    )
    isk = hashlib.sha512(isk_input).digest()
    transcript = cbor_array(
        [
            cbor_bytes(inputs["public_context"]),
            cbor_bytes(inputs["allocator_frame"]),
            cbor_bytes(inputs["claimant_frame"]),
        ]
    )
    th = hashlib.sha512(transcript).digest()
    prk = hmac.new(b"", isk, hashlib.sha512).digest()

    labels = {
        "kc_allocator": (b"pairing-credential-v2 kc A", 32),
        "kc_claimant": (b"pairing-credential-v2 kc B", 32),
        "key_allocator_to_claimant": (b"pairing-credential-v2 key A-B", 32),
        "key_claimant_to_allocator": (b"pairing-credential-v2 key B-A", 32),
        "iv_allocator_to_claimant": (b"pairing-credential-v2 iv A-B", 12),
        "iv_claimant_to_allocator": (b"pairing-credential-v2 iv B-A", 12),
        "exporter": (b"pairing-credential-v2 exporter", 32),
    }
    outputs = {
        name: hkdf_expand(prk, label + th, length)
        for name, (label, length) in labels.items()
    }
    outputs["isk"] = isk
    outputs["th"] = th
    outputs["prk"] = prk
    outputs["finished_allocator"] = hmac.new(
        outputs["kc_allocator"],
        b"pairing-credential-v2 finished A" + th,
        hashlib.sha512,
    ).digest()
    outputs["finished_claimant"] = hmac.new(
        outputs["kc_claimant"],
        b"pairing-credential-v2 finished B" + th,
        hashlib.sha512,
    ).digest()
    aad = cbor_map(
        [
            (cbor_text("v"), cbor_uint(2)),
            (cbor_text("direction"), cbor_uint(0)),
            (cbor_text("counter"), cbor_uint(0)),
            (cbor_text("th"), cbor_bytes(th)),
        ]
    )
    nonce = bytearray(outputs["iv_allocator_to_claimant"])
    counter = (0).to_bytes(8, "big")
    for index, octet in enumerate(counter, start=4):
        nonce[index] ^= octet
    outputs["aad_allocator_counter_zero"] = aad
    outputs["nonce_allocator_counter_zero"] = bytes(nonce)
    outputs["ciphertext_allocator_counter_zero"] = AESGCM(
        outputs["key_allocator_to_claimant"]
    ).encrypt(bytes(nonce), inputs["plaintext"], aad)

    json.dump({key: value.hex() for key, value in outputs.items()}, sys.stdout)


if __name__ == "__main__":
    main()
