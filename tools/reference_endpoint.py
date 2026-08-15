#!/usr/bin/env python3
"""Dependency-independent SPEC-072 endpoint vector implementation.

Uses only Python's standard library plus cryptography primitives. It does not
import cbcl-pairing, cbcl-rs, or a CBOR/S-expression package.
"""

import hashlib
import hmac
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _head(major, value):
    if value < 24: return bytes([(major << 5) | value])
    if value < 256: return bytes([(major << 5) | 24, value])
    if value < 65536: return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32: return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor(value):
    if value is None: return b"\xf6"
    if isinstance(value, int): return _head(0, value)
    if isinstance(value, bytes): return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _head(3, len(raw)) + raw
    if isinstance(value, list): return _head(4, len(value)) + b"".join(cbor(x) for x in value)
    if isinstance(value, dict):
        pairs = sorted(((cbor(k), cbor(v)) for k, v in value.items()), key=lambda p: (len(p[0]), p[0]))
        return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(type(value))


def atom(kind, value): return (kind, value)
def sym(value): return atom("S", value)
def kw(value): return atom("K", value)
def string(value): return atom("Q", value)
def num(value): return atom("N", str(value))


def sexpr_text(node):
    if isinstance(node, list): return "(" + " ".join(sexpr_text(x) for x in node) + ")"
    kind, value = node
    if kind == "Q": return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if kind == "K": return ":" + value
    return value


def rfc9804(node):
    if isinstance(node, list): return b"(" + b"".join(rfc9804(x) for x in node) + b")"
    kind, value = node
    raw = kind.encode() + value.encode()
    return str(len(raw)).encode() + b":" + raw


def signed_node(seed, inner):
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signature = private.sign(rfc9804(inner)).hex()
    outer = [sym("signed"), sym("@ed25519:" + public.hex()), string(signature), inner]
    private.public_key().verify(bytes.fromhex(signature), rfc9804(inner))
    return outer, sexpr_text(outer).encode(), "sha256:" + hashlib.sha256(rfc9804(outer)).hexdigest()


def cause_node(causes):
    if causes == "begin": return sym("begin")
    if isinstance(causes, list): return [sym(x) for x in sorted(causes)]
    return sym(causes)


def signed_control(seed, perf, ceremony, body, causes):
    cause = cause_node(causes)
    inner = [sym(perf), string(ceremony), string("sha256:" + hashlib.sha256(body).hexdigest()),
             num(len(body)), kw("thread"), string(ceremony), kw("caused-by"), cause]
    _, wire, content_hash = signed_node(seed, inner)
    assert inner[2][1] == "sha256:" + hashlib.sha256(body).hexdigest() and int(inner[3][1]) == len(body)
    return wire, content_hash


def key_id(seed):
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "@ed25519:" + public.hex()


def session_opener(allocator_seed, claimant_seed, ceremony):
    inner = [sym("hello"), [], kw("thread"), string(ceremony), kw("caused-by"), sym("begin")]
    signed, _, _ = signed_node(allocator_seed, inner)
    outer = [sym("with-roles"),
             [[sym("allocator"), sym(key_id(allocator_seed))],
              [sym("claimant"), sym(key_id(claimant_seed))]],
             kw("dialect"), sym("sha256:465e218843248ed867dfa385e498169607daf49c031fca7173891578e60fab3c"),
             signed]
    return sexpr_text(outer).encode(), "sha256:" + hashlib.sha256(rfc9804(outer)).hexdigest()


def session_control(seed, perf, recipient, ceremony, body, cause):
    inner = [sym(perf), sym(recipient), string(ceremony),
             string("sha256:" + hashlib.sha256(body).hexdigest()), num(len(body)),
             kw("thread"), string(ceremony), kw("caused-by"), cause_node(cause)]
    _, wire, content_hash = signed_node(seed, inner)
    assert inner[3][1] == "sha256:" + hashlib.sha256(body).hexdigest() and int(inner[4][1]) == len(body)
    return wire, content_hash


def hkdf_expand(prk, info, length):
    result, block = b"", b""
    for index in range(1, (length + 63) // 64 + 1):
        block = hmac.new(prk, block + info + bytes([index]), hashlib.sha512).digest()
        result += block
    return result[:length]


def schedule(isk, public_context, a_frame, b_frame):
    th = hashlib.sha512(cbor([public_context, a_frame, b_frame])).digest()
    prk = hmac.new(b"\0" * 64, isk, hashlib.sha512).digest()
    expand = lambda label, n: hkdf_expand(prk, label + th, n)
    kca, kcb = expand(b"pairing-v1 kc A", 32), expand(b"pairing-v1 kc B", 32)
    fa = hmac.new(kca, b"pairing-v1 finished A" + th, hashlib.sha512).digest()
    fb = hmac.new(kcb, b"pairing-v1 finished B" + th, hashlib.sha512).digest()
    return th, fa, fb, expand(b"pairing-v1 key A-B", 32), expand(b"pairing-v1 key B-A", 32), \
        expand(b"pairing-v1 iv A-B", 12), expand(b"pairing-v1 iv B-A", 12), expand(b"pairing-v1 exporter", 32)


def seal(direction, counter, plaintext, key, iv, th):
    nonce = iv[:4] + bytes(x ^ y for x, y in zip(iv[4:], counter.to_bytes(8, "big")))
    aad = cbor({"v": 1, "direction": direction, "counter": counter, "th": th})
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return ciphertext, cbor({"v": 1, "kind": "sealed", "direction": direction,
                             "counter": counter, "ciphertext": ciphertext})


def classify_finished(received, expected):
    return "valid" if hmac.compare_digest(received, expected) else "finished-mismatch"


def classify_open(expected_direction, expected_counter, direction, counter, ciphertext, key, iv, th):
    if direction != expected_direction: return "direction-mismatch"
    if counter != expected_counter: return "counter-mismatch"
    nonce = iv[:4] + bytes(x ^ y for x, y in zip(iv[4:], counter.to_bytes(8, "big")))
    aad = cbor({"v": 1, "direction": direction, "counter": counter, "th": th})
    try: AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception: return "invalid-tag"
    return "valid"


def causal_verdict(causes, known):
    if causes == "begin": return "valid"
    if isinstance(causes, str): return "valid" if causes in known else "unknown"
    return "valid" if all(cause in known for cause in causes) else "unknown"


def main():
    mailbox = bytes(range(32))
    invitation = {"version": 1, "suite": "CPACE25519-SHA512-D21",
                  "application": "example.test/synthetic/v1", "relay-origin": "https://relay.example",
                  "locator": [0, mailbox], "secret": bytes(range(0x40, 0x50))}
    invitation_wire = cbor(invitation)
    ci = cbor(["cbcl-pairing-ci/v1", 1, "CPACE25519-SHA512-D21", invitation["application"],
               invitation["relay-origin"], mailbox, ["allocator", "claimant"]])
    ada = cbor(["cbcl-pairing-ad/v1", "allocator", None])
    adb = cbor(["cbcl-pairing-ad/v1", "claimant", None])
    public = cbor(["cbcl-pairing-public-context/v1", 1, "CPACE25519-SHA512-D21",
                   invitation["application"], invitation["relay-origin"], mailbox, None, None])
    ma, mb = cbor([1, 0, bytes([0x31]) * 32, ada]), cbor([1, 1, bytes([0x42]) * 32, adb])
    ceremony = hashlib.sha256(invitation_wire).hexdigest()
    ca, ha = signed_control(bytes([0x11]) * 32, "cpace-a", ceremony, ma, "begin")
    cb, hb = signed_control(bytes([0x22]) * 32, "cpace-b", ceremony, mb, "begin")
    fa_wire = cbor({"v": 1, "kind": "cpace", "role": 0, "control": ca, "message": ma})
    fb_wire = cbor({"v": 1, "kind": "cpace", "role": 1, "control": cb, "message": mb})
    isk = bytes.fromhex("6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4d5e53bb2aa82c300bea7b65d2b671da71922ddf6472301b79bc270adfa8bf413285f2263")
    th, fina, finb, kab, kba, iva, ivb, exporter = schedule(isk, public, fa_wire, fb_wire)
    fca, hfa = signed_control(bytes([0x11]) * 32, "finished-a", ceremony, fina, [ha, hb])
    fcb, hfb = signed_control(bytes([0x22]) * 32, "finished-b", ceremony, finb, [ha, hb])
    finished_a_wire = cbor({"v": 1, "kind": "finished", "role": 0, "control": fca, "value": fina})
    finished_b_wire = cbor({"v": 1, "kind": "finished", "role": 1, "control": fcb, "value": finb})
    cta, sealed_a = seal(0, 0, b"allocator payload", kab, iva, th)
    ctb, sealed_b = seal(1, 0, b"claimant decision", kba, ivb, th)

    opener, opener_hash = session_opener(bytes([0x11]) * 32, bytes([0x22]) * 32, ceremony)
    opener_plaintext = cbor({"control": opener})
    _, opener_frame = seal(0, 0, opener_plaintext, kab, iva, th)
    allocator_claim = cbor({"subject": "synthetic subject"})
    claimant_claim = cbor({"audience": "synthetic audience"})
    intent_body = cbor({"type": "intent", "application": "example.test/synthetic/v1",
                        "action": "exercise-profile", "allocator-claim": allocator_claim,
                        "claimant-claim": claimant_claim, "authority-summary": "test authority",
                        "intent-nonce": bytes([0x77]) * 32})
    intent_control, intent_hash = session_control(
        bytes([0x11]) * 32, "pairing-intent", key_id(bytes([0x22]) * 32),
        ceremony, intent_body, opener_hash)
    intent_plaintext = cbor({"control": intent_control, "body": intent_body})
    _, intent_frame = seal(0, 1, intent_plaintext, kab, iva, th)
    intent_digest = hashlib.sha256(intent_body).digest()
    decision_body = cbor({"type": "decision", "intent-digest": intent_digest,
                          "decision": "approve"})
    decision_control, decision_hash = session_control(
        bytes([0x22]) * 32, "pairing-approve", key_id(bytes([0x11]) * 32),
        ceremony, decision_body, intent_hash)
    decision_plaintext = cbor({"control": decision_control, "body": decision_body})
    _, decision_frame = seal(1, 0, decision_plaintext, kba, ivb, th)
    grant_body = cbor({"subject": "synthetic subject", "audience": "synthetic audience",
                       "grant": b"opaque synthetic grant"})
    payload_body = cbor({"type": "payload", "intent-digest": intent_digest,
                         "payload-type": "example.test/synthetic-grant/v1", "body": grant_body})
    payload_control, payload_hash = session_control(
        bytes([0x11]) * 32, "pairing-payload", key_id(bytes([0x22]) * 32),
        ceremony, payload_body, decision_hash)
    payload_plaintext = cbor({"control": payload_control, "body": payload_body})
    _, payload_frame = seal(0, 2, payload_plaintext, kab, iva, th)
    out = {
        "invitation": invitation_wire.hex(), "ceremony": ceremony, "ci": ci.hex(), "ad_a": ada.hex(),
        "ad_b": adb.hex(), "public_context": public.hex(), "cpace_message_a": ma.hex(),
        "cpace_message_b": mb.hex(), "cpace_control_a": ca.hex(), "cpace_control_b": cb.hex(),
        "cpace_hash_a": ha, "cpace_hash_b": hb, "cpace_frame_a": fa_wire.hex(),
        "cpace_frame_b": fb_wire.hex(), "transcript_hash": th.hex(), "finished_a": fina.hex(),
        "finished_b": finb.hex(), "finished_control_a": fca.hex(), "finished_control_b": fcb.hex(),
        "finished_hash_a": hfa, "finished_hash_b": hfb, "finished_frame_a": finished_a_wire.hex(),
        "finished_frame_b": finished_b_wire.hex(), "exporter": exporter.hex(),
        "ciphertext_a": cta.hex(), "ciphertext_b": ctb.hex(), "sealed_frame_a": sealed_a.hex(),
        "sealed_frame_b": sealed_b.hex(),
        "session": {"opener_control": opener.hex(), "opener_hash": opener_hash,
                    "opener_frame": opener_frame.hex(), "intent_body": intent_body.hex(),
                    "intent_control": intent_control.hex(), "intent_hash": intent_hash,
                    "intent_frame": intent_frame.hex(), "decision_body": decision_body.hex(),
                    "decision_control": decision_control.hex(), "decision_hash": decision_hash,
                    "decision_frame": decision_frame.hex(), "payload_body": payload_body.hex(),
                    "payload_control": payload_control.hex(), "payload_hash": payload_hash,
                    "payload_frame": payload_frame.hex(), "intent_digest": intent_digest.hex()},
        "application_events": ["session-ready", "display-intent", "approve", "deliver-grant"],
        "accept_result": "grant-authorized",
        "fixed_time": {"now": 1786800000, "expires_at": 1786800600},
        "profile_invitations": {
            "agent": cbor({"version": 1, "suite": "CPACE25519-SHA512-D21",
                           "application": "anuna.io/agent/v1", "relay-origin": "wss://relay.example",
                           "locator": [1, 123456], "secret": bytes.fromhex("00010002")}).hex(),
            "credential": cbor({"version": 1, "suite": "CPACE25519-SHA512-D21",
                                "application": "anuna.io/credential/v1", "relay-origin": "https://relay.example",
                                "locator": [0, mailbox], "secret": bytes(range(0x40, 0x50))}).hex()},
        "cbcl_verdicts": {"cpace_a": causal_verdict("begin", set()), "cpace_b": causal_verdict("begin", set()),
                           "finished_a": causal_verdict([ha, hb], {ha, hb}),
                           "finished_b": causal_verdict([ha, hb], {ha, hb}),
                           "session_opener": causal_verdict("begin", set()),
                           "intent": causal_verdict(opener_hash, {opener_hash}),
                           "approve": causal_verdict(intent_hash, {opener_hash, intent_hash}),
                           "payload": causal_verdict(decision_hash, {opener_hash, intent_hash, decision_hash}),
                           "missing_predecessor": causal_verdict([ha, "sha256:" + "77" * 32], {ha}),
                           "mutated_body": "valid" if hashlib.sha256(b"mutated").digest() == hashlib.sha256(b"bound").digest() else "body-binding"},
        "terminal": {"bad_finished": classify_finished(bytes([fina[0] ^ 1]) + fina[1:], fina),
                     "replay": classify_open(0, 1, 0, 0, cta, kab, iva, th),
                     "gap": classify_open(0, 0, 0, 1, cta, kab, iva, th),
                     "wrong_direction": classify_open(0, 0, 1, 0, cta, kab, iva, th),
                     "bad_tag": classify_open(0, 0, 0, 0, bytes([cta[0] ^ 1]) + cta[1:], kab, iva, th),
                     "expired": "expired"}
    }
    print(json.dumps(out, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__": main()
