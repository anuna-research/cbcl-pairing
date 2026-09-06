#!/usr/bin/env python3
"""Independent SPEC-078 / SPEC-001 TEST-066 synthetic vectors.

Python stdlib CBOR/hash/field arithmetic and cryptography X25519 only.
No Rust outputs are inputs. CPace generator follows draft-21 Appendix A.5:
https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21#appendix-A.5
Regenerate: python3 tests/support/manual_vectors.py > vectors/credential-v2-manual.json
Optional argument: path to bip39-2.2.2/src/language/english.rs.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from handoff_vectors import cbor as basic_cbor, head
from credential_v2_oracle import length_value as lv, hkdf_expand


def cbor(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(cbor, value))
    return basic_cbor(value)


def words_vector(n, words):
    checksum = hashlib.sha256(b'selfsame-pairing-manual-words/v1\0' + n.to_bytes(4, 'big')).digest()[0] >> 5
    packed = n * 8 + checksum
    indices = [(packed // (2 ** shift)) % 2048 for shift in (22, 11, 0)]
    return dict(n=n, checksum=checksum, indices=indices, words=' '.join(words[i] for i in indices),
                c_hex='5353504149522d4d31000000' + n.to_bytes(4, 'big').hex())


def carrier_values(maximum):
    mailbox = bytes(range(32))
    t = bytes(range(240, 256))
    return {
        'version': 2, 'profile': 'anuna.io/credential/v2', 'profile-version': 2,
        'application-context': 'https://a/' + 'x' * (2038 if maximum else 1),
        'relay-origin': 'https://' + 'r' * (264 if maximum else 1),
        'locator': mailbox, 'carrier-ceremony-id': bytes([0x23]) * 32,
        'carrier-nonce': bytes([0x45]) * 32,
        'claim-commitment': hashlib.sha256(b'cbcl-pairing claim-v2 commitment\0' + mailbox + t).digest(),
        'relay-expires-at': 2**64-1 if maximum else 1,
        'expected-allocator-key': bytes([0x67]) * 32,
    }, t


def bootstrap_vector(maximum):
    carrier, t = carrier_values(maximum)
    public = cbor(carrier)
    raw = cbor(['selfsame-pairing-manual/v1', public, t])
    text = 'SSPAIR-M1:' + base64.urlsafe_b64encode(raw).decode().rstrip('=')
    if maximum:
        assert (len(public), len(raw), len(text)) == (2695, 2744, 3669)
    return dict(name='maximum' if maximum else 'minimum_keyed_live', carrier_hex=public.hex(),
                carrier_len=len(public), decoded_len=len(raw), text_len=len(text),
                carrier_sha256=hashlib.sha256(public).hexdigest(), commitment_hex=carrier['claim-commitment'].hex(),
                t_hex=t.hex(), decoded_hex=raw.hex(), bootstrap=text)


def generator(prs, ci, sid):
    prefix = lv(b'CPace255') + lv(prs)
    data = prefix + lv(bytes(max(0, 127 - len(prefix)))) + lv(ci) + lv(sid)
    p = 2**255-19
    r = (int.from_bytes(hashlib.sha512(data).digest()[:32], 'little') % 2**255) % p
    v = -486662 * pow(1 + 2*r*r, -1, p) % p
    legendre = pow((v**3 + 486662*v*v + v) % p, (p-1)//2, p)
    u = (legendre*v - (1-legendre)*486662*pow(2, -1, p)) % p
    return u.to_bytes(32, 'little')


def cpace_vector(c):
    # Check the independent field construction against the pinned draft's vector.
    assert generator(b'Password', b'\x0bA_initiator\x0bB_responder', bytes.fromhex('7e4b4791d6a8ef019b936c79fb7f2c57')).hex() == 'd04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f'
    carrier, _ = carrier_values(False)
    carrier['relay-expires-at'] = 1800000900
    raw = cbor(carrier)
    pd = bytes([0x89])*32
    cd = hashlib.sha256(raw).digest()
    tail = [2, 'CPACE25519-SHA512-D21', 'anuna.io/credential/v2', carrier['application-context'], pd, cd,
            carrier['relay-origin'], carrier['locator'], carrier['carrier-ceremony-id'], carrier['claim-commitment']]
    ci = cbor(['cbcl-pairing-ci/credential-v2'] + tail + [['allocator', 'claimant']])
    public = cbor(['cbcl-pairing-public-context/credential-v2'] + tail + [carrier['expected-allocator-key'], None])
    ad = [cbor(['cbcl-pairing-ad/credential-v2', side, key, pd, cd]) for side, key in
          [('allocator', carrier['expected-allocator-key']), ('claimant', None)]]
    scalars = [bytes([0xab])*32, bytes([0xcd])*32]
    g = generator(c, ci, carrier['locator'])
    shares = [X25519PrivateKey.from_private_bytes(s).exchange(X25519PublicKey.from_public_bytes(g)) for s in scalars]
    frames = [cbor({'v': 2, 'kind': 'cpace', 'role': i, 'message': cbor([2, i, shares[i], ad[i]])}) for i in range(2)]
    shared = X25519PrivateKey.from_private_bytes(scalars[0]).exchange(X25519PublicKey.from_public_bytes(shares[1]))
    assert shared == X25519PrivateKey.from_private_bytes(scalars[1]).exchange(X25519PublicKey.from_public_bytes(shares[0]))
    isk = hashlib.sha512(b''.join(map(lv, [b'CPace255_ISK', carrier['locator'], shared, shares[0], ad[0], shares[1], ad[1]]))).digest()
    th = hashlib.sha512(cbor([public] + frames)).digest()
    prk = hmac.new(b'', isk, hashlib.sha512).digest()
    finished = [hmac.new(hkdf_expand(prk, b'pairing-credential-v2 kc ' + role + th, 32),
                         b'pairing-credential-v2 finished ' + role + th, hashlib.sha512).digest() for role in [b'A', b'B']]
    values = dict(c=c, carrier=raw, profile_digest=pd, ci=ci, public_context=public, generator=g, isk=isk, th=th, prk=prk)
    for i, side in enumerate(['allocator', 'claimant']):
        values.update({side+'_scalar': scalars[i], side+'_share': shares[i], side+'_ad': ad[i], side+'_frame': frames[i], side+'_finished': finished[i]})
    return {key+'_hex': value.hex() for key, value in values.items()}


def main():
    path = Path(sys.argv[1]) if len(sys.argv)>1 else next((Path.home()/'.cargo/registry/src').glob('*/bip39-2.2.2/src/language/english.rs'))
    words = re.findall(r'"([a-z]+)"', path.read_text())
    assert len(words) == 2048 and all(3 <= len(w) <= 8 for w in words)
    digest = hashlib.sha256(('\n'.join(words)+'\n').encode()).hexdigest()
    assert digest == '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda'
    chosen = {0, 1, 2**30-1, 0x12345678}
    branches = set()
    for n in range(1000):
        check = words_vector(n, words)['checksum']
        if check not in branches:
            chosen.add(n)
            branches.add(check)
        if len(branches) == 8:
            break
    vectors = [words_vector(n, words) for n in sorted(chosen)]
    json.dump(dict(word_list_sha256=digest, words=vectors,
                   bootstraps=[bootstrap_vector(False), bootstrap_vector(True)],
                   cpace=cpace_vector(bytes.fromhex(words_vector(0x12345678, words)['c_hex']))), sys.stdout, indent=2)
    print()


if __name__ == '__main__':
    main()
