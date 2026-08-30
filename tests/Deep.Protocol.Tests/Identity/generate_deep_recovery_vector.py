import hashlib
import hmac
import json
import struct


MNEMONIC = " ".join(["abandon"] * 23 + ["art"])
NETWORK_ID = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
GENERATION = 1


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        output += block
        counter += 1
    return output[:length]


def expand_role(prk: bytes, domain: str, context: bytes) -> bytes:
    info = domain.encode("ascii") + b"\x00" + struct.pack(">I", len(context)) + context
    return hkdf_expand(prk, info, 32)


bip39_seed = hashlib.pbkdf2_hmac(
    "sha512", MNEMONIC.encode("utf-8"), b"mnemonic", 2048, dklen=64
)
extract_salt = hashlib.sha512(b"Deep/Recovery/V1/extract").digest()
prk = hkdf_extract(extract_salt, bip39_seed)
context = NETWORK_ID + struct.pack(">Q", GENERATION)
address_context = b"DeepGlobalAddressV1"

vector = {
    "entropy": "00" * 32,
    "mnemonic": MNEMONIC,
    "networkId": NETWORK_ID.hex(),
    "accountGeneration": str(GENERATION),
    "bip39Seed": bip39_seed.hex(),
    "accountSigningSeed": expand_role(
        prk, "Deep/Recovery/V1/account-signing-seed", context
    ).hex(),
    "deviceIssuerSigningSeed": expand_role(
        prk, "Deep/Recovery/V1/device-issuer-signing-seed", context
    ).hex(),
    "accountRevocationSigningSeed": expand_role(
        prk, "Deep/Recovery/V1/revocation-signing-seed", context
    ).hex(),
    "resetControlSigningSeed": expand_role(
        prk, "Deep/Recovery/V1/reset-control-signing-seed", context
    ).hex(),
    "backupWrappingSeed": expand_role(
        prk, "Deep/Recovery/V1/backup-wrapping-seed", context
    ).hex(),
    "addressSigningSeed": expand_role(
        prk, "Deep/Recovery/V1/public-address-signing-seed", address_context
    ).hex(),
    "addressReadCapability": hkdf_expand(
        prk,
        b"Deep/Recovery/V1/public-address-read-capability\x00"
        + struct.pack(">I", len(address_context))
        + address_context,
        16,
    ).hex(),
}

print(json.dumps(vector, indent=2, sort_keys=True))
