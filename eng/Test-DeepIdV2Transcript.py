#!/usr/bin/env python3
"""Independent DID2/DAB2 draft transcript oracle for a public BIP-39 phrase.

The native probe is test-only. This script never reads user recovery material.
It prints only public record hashes and signature digests, not secret seeds.
"""

import argparse
import hashlib
import hmac
import json
import struct
import subprocess
from pathlib import Path

from nacl.signing import SigningKey


MNEMONIC = ("abandon " * 23 + "art").encode("ascii")
SUITE = 0x0301
CONTEXT = b"DeepGlobalPqRootV2"
NETWORK = bytes(range(16))
BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def lp32(value):
    return struct.pack(">I", len(value)) + value


def hkdf_expand(prk, info, length):
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        output += block
        counter += 1
    return output[:length]


def derive(label, prk, context, length):
    return hkdf_expand(prk, label.encode("ascii") + b"\0" + lp32(context), length)


def domain_hash(label, value):
    return hashlib.sha256(label.encode("ascii") + b"\0" + lp32(value)).digest()


def record(magic, fields, count=None):
    if count is None:
        count = len(fields)
    result = magic.encode("ascii") + struct.pack(">HHHH", 2, SUITE, count, 0)
    for tag, value in enumerate(fields, 1):
        result += struct.pack(">HHI", tag, 0, len(value)) + value
    return result


def sign_input(label, unsigned):
    return label.encode("ascii") + b"\0" + struct.pack(">H", SUITE) + lp32(unsigned)


def bech32_polymod(values):
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                  0x3d4233dd, 0x2a1462b3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def bech32m(payload):
    hrp = "deep"
    symbols = []
    accumulator = 0
    bits = 0
    for byte in payload:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            symbols.append((accumulator >> bits) & 31)
    if bits:
        symbols.append((accumulator << (5 - bits)) & 31)

    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = bech32_polymod(expanded + symbols + [0] * 6) ^ 0x2bc830a3
    symbols += [(checksum >> (5 * (5 - index))) & 31 for index in range(6)]
    result = hrp + "1" + "".join(BECH32_CHARS[value] for value in symbols)
    if len(result) != 90:
        raise ValueError("The compact Deep ID must be exactly 90 characters")
    return result


def decode_bech32m(value):
    if len(value) != 90 or not value.startswith("deep1") or value != value.lower():
        raise ValueError("Deep ID text shape changed")
    try:
        symbols = [BECH32_CHARS.index(character) for character in value[5:]]
    except ValueError as exception:
        raise ValueError("Deep ID text character is invalid") from exception
    expanded = [ord(c) >> 5 for c in "deep"] + [0] + [ord(c) & 31 for c in "deep"]
    if bech32_polymod(expanded + symbols) != 0x2bc830a3:
        raise ValueError("Deep ID Bech32m checksum mismatch")
    accumulator = 0
    bits = 0
    payload = bytearray()
    for symbol in symbols[:-6]:
        accumulator = (accumulator << 5) | symbol
        bits += 5
        if bits >= 8:
            bits -= 8
            payload.append((accumulator >> bits) & 255)
    if bits >= 5 or (accumulator & ((1 << bits) - 1)) != 0:
        raise ValueError("Deep ID text has noncanonical padding")
    if len(payload) != 49 or payload[0] != 2:
        raise ValueError("Deep ID text has unsupported payload")
    return bytes(payload)


def native_public_and_signature(probe, seed, message):
    if len(seed) != 32 or not 1 <= len(message) <= 512:
        raise ValueError("Unexpected native transcript input length")
    result = subprocess.run(
        [str(probe)], input=seed + struct.pack(">H", len(message)) + message,
        capture_output=True, check=True)
    if result.stderr or len(result.stdout) != 1952 + 3309:
        raise ValueError("Unexpected native transcript output")
    return result.stdout[:1952], result.stdout[1952:]


def native_verify(probe, public_key, message, signature):
    payload = public_key + struct.pack(">H", len(message)) + message + signature
    result = subprocess.run([str(probe), "--verify"], input=payload,
                            capture_output=True, check=False)
    if result.stdout or result.stderr:
        raise ValueError("Unexpected native verification output")
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    args = parser.parse_args()
    probe = args.probe.resolve()
    bip39 = hashlib.pbkdf2_hmac("sha512", MNEMONIC, b"mnemonic", 2048, 64)
    root_salt = hashlib.sha512(b"Deep/Recovery/V2/PQ-root/extract").digest()
    root_prk = hmac.new(root_salt, bip39, hashlib.sha512).digest()
    ed_seed = derive("Deep/Recovery/V2/root-ed25519-signing-seed", root_prk, CONTEXT, 32)
    pq_seed = derive("Deep/Recovery/V2/root-mldsa65-signing-seed", root_prk, CONTEXT, 32)
    capability = derive("Deep/Recovery/V2/root-resolver-read-capability", root_prk, CONTEXT, 16)
    pq_public, _ = native_public_and_signature(probe, pq_seed, bytes(250))
    ed = SigningKey(ed_seed)
    did = record("DID2", [bytes(ed.verify_key), pq_public, capability])
    if len(did) != 2036:
        raise ValueError("DID2 size changed")
    did_hash = domain_hash("Deep/Application/V2/record-hash/DID2", did)
    text = bech32m(b"\x02" + did_hash + capability)
    if decode_bech32m(text) != b"\x02" + did_hash + capability:
        raise ValueError("Deep ID text did not round trip")
    for malformed in (text.upper(), text[:-1] + ("q" if text[-1] != "q" else "p")):
        try:
            decode_bech32m(malformed)
        except ValueError:
            pass
        else:
            raise ValueError("Deep ID text accepted a noncanonical mutation")

    old_salt = hashlib.sha512(b"Deep/Recovery/V1/extract").digest()
    old_prk = hmac.new(old_salt, bip39, hashlib.sha512).digest()
    account_seed = derive("Deep/Recovery/V1/account-signing-seed", old_prk,
                          NETWORK + struct.pack(">Q", 1), 32)
    account = SigningKey(account_seed)
    realm = domain_hash("Deep/Application/V2/address-binding-realm",
                        NETWORK + struct.pack(">H", 1))
    account_id = domain_hash("Deep/Identity/V1/account-id", bytes(account.verify_key))
    dpa_reference = struct.pack(">HI", 1, 644) + hashlib.sha256(b"DID2 transcript DPA1 reference").digest()
    unsigned = record("DAB2", [did_hash, realm, struct.pack(">Q", 0),
                               bytes(32), account_id, struct.pack(">Q", 1),
                               dpa_reference], count=7)
    if len(unsigned) != 250:
        raise ValueError("DAB2 unsigned size changed")
    ed_input = sign_input("Deep/Application/V2/address-binding/root-ed25519", unsigned)
    pq_input = sign_input("Deep/Application/V2/address-binding/root-mldsa65", unsigned)
    account_input = sign_input("Deep/Application/V2/address-binding/account-ed25519", unsigned)
    ed_signature = ed.sign(ed_input).signature
    pq_public_again, pq_signature = native_public_and_signature(probe, pq_seed, pq_input)
    if pq_public_again != pq_public:
        raise ValueError("ML-DSA public key changed between transcript calls")
    if not native_verify(probe, pq_public, pq_input, pq_signature):
        raise ValueError("ML-DSA signature did not verify")
    tampered = bytearray(pq_input)
    tampered[-1] ^= 1
    if native_verify(probe, pq_public, tampered, pq_signature):
        raise ValueError("ML-DSA signature accepted changed transcript")
    substitute_seed = hashlib.sha256(pq_seed + b"public vector substitute").digest()
    substitute_public, _ = native_public_and_signature(probe, substitute_seed, pq_input)
    if native_verify(probe, substitute_public, pq_input, pq_signature):
        raise ValueError("ML-DSA signature accepted a substituted root key")
    account_signature = account.sign(account_input).signature
    dab = record("DAB2", [did_hash, realm, struct.pack(">Q", 0), bytes(32),
                           account_id, struct.pack(">Q", 1), dpa_reference,
                           ed_signature, pq_signature, account_signature])
    if len(dab) != 3711:
        raise ValueError("DAB2 size changed")
    ed.verify_key.verify(ed_input, ed_signature)
    account.verify_key.verify(account_input, account_signature)
    try:
        ed.verify_key.verify(ed_input[:-1] + bytes([ed_input[-1] ^ 1]), ed_signature)
    except Exception:
        pass
    else:
        raise ValueError("Ed25519 root signature accepted changed transcript")
    actual = {
        "didSha256": hashlib.sha256(did).hexdigest(),
        "didRecordHash": did_hash.hex(),
        "deepIdText": text,
        "dabUnsignedSha256": hashlib.sha256(unsigned).hexdigest(),
        "dabSha256": hashlib.sha256(dab).hexdigest(),
        "dabRecordHash": domain_hash("Deep/Application/V2/record-hash/DAB2", dab).hex(),
        "rootEdSignatureSha256": hashlib.sha256(ed_signature).hexdigest(),
        "rootPqSignatureSha256": hashlib.sha256(pq_signature).hexdigest(),
        "accountSignatureSha256": hashlib.sha256(account_signature).hexdigest(),
    }
    vector_path = Path(__file__).resolve().parents[1] / "registry/deep-id-v2.vectors.json"
    expected_values = json.loads(vector_path.read_text(encoding="utf-8"))["expected"]
    if set(expected_values) != set(actual):
        raise ValueError("DID2/DAB2 vector keys changed")
    for key, expected in expected_values.items():
        if actual[key] != expected:
            raise ValueError(f"DID2/DAB2 pinned transcript changed: {key}")
    print("PASS pinned DID2/DAB2 transcript (9 values), Ed/ML-DSA verification and mutation rejection")


if __name__ == "__main__":
    main()
