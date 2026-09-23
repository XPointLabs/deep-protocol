#!/usr/bin/env python3
"""Test the Deep ML-DSA-65 C ABI against pinned official ACVP vectors.

The vector seeds and keys are public test material. Never use them for accounts.
Only the external pure-message interface is supported by the Deep ABI; this
script does not claim coverage of prehash, external-mu, or expanded-key APIs.
"""

import argparse
import ctypes
import hashlib
import hmac
import json
from pathlib import Path
from urllib.request import Request, urlopen


VERSION = "v1.1.0.43"
BASE_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    f"{VERSION}/gen-val/json-files"
)
MAX_VECTOR_BYTES = 10_000_000
PINS = {
    "ML-DSA-keyGen-FIPS204/prompt.json":
        "43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef",
    "ML-DSA-keyGen-FIPS204/expectedResults.json":
        "361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df",
    "ML-DSA-sigGen-FIPS204-tr1/prompt.json":
        "0a81a213fb4825f0a9d8893a20445a3fed88a6f1832703548120b9588c74a08e",
    "ML-DSA-sigGen-FIPS204-tr1/expectedResults.json":
        "8d86d120d128d2f2d29afb7843b7351677ac0f1bf649295d85b7bf3dd533949c",
    "ML-DSA-sigVer-FIPS204/prompt.json":
        "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
    "ML-DSA-sigVer-FIPS204/expectedResults.json":
        "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
}


def load_vector(name, root):
    if root is None:
        request = Request(f"{BASE_URL}/{name}", headers={"User-Agent": "Deep-MLDSA-ACVP/1"})
        with urlopen(request, timeout=45) as response:
            data = response.read(MAX_VECTOR_BYTES + 1)
    else:
        data = (root / name).read_bytes()
    if len(data) > MAX_VECTOR_BYTES:
        raise ValueError(f"Oversized ACVP vector file: {name}")
    if hashlib.sha256(data).hexdigest() != PINS[name]:
        raise ValueError(f"ACVP vector digest mismatch: {name}")
    value = json.loads(data)
    if value.get("algorithm") != "ML-DSA" or value.get("revision") not in ("FIPS204", "FIPS204-tr1"):
        raise ValueError(f"Unexpected ACVP vector header: {name}")
    return value


def bind(library, name, count):
    function = getattr(library, name)
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t] * count
    function.restype = ctypes.c_int32
    return function


def input_buffer(data):
    return ctypes.create_string_buffer(data, max(1, len(data)))


def output_buffer(length):
    return ctypes.create_string_buffer(length)


def expected_by_id(document, group_id):
    groups = [group for group in document["testGroups"] if group["tgId"] == group_id]
    if len(groups) != 1:
        raise ValueError(f"Missing or duplicate expected group: {group_id}")
    return {case["tcId"]: case for case in groups[0]["tests"]}


def run_keygen(library, prompt, expected):
    derive = bind(library, "deep_mldsa_v1_public_from_seed", 2)
    count = 0
    for group in prompt["testGroups"]:
        if group.get("parameterSet") != "ML-DSA-65":
            continue
        if group.get("testType") != "AFT":
            raise ValueError("Unexpected ML-DSA-65 keyGen test type")
        cases = expected_by_id(expected, group["tgId"])
        for case in group["tests"]:
            seed = bytes.fromhex(case["seed"])
            reference = bytes.fromhex(cases[case["tcId"]]["pk"])
            if len(seed) != 32 or len(reference) != 1952:
                raise ValueError("Unexpected keyGen vector length")
            source, destination = input_buffer(seed), output_buffer(1952)
            result = derive(source, len(seed), destination, 1952)
            if result != 0 or not hmac.compare_digest(destination.raw, reference):
                raise ValueError(f"Deep ABI keyGen failed ACVP tcId={case['tcId']}")
            count += 1
    if count != 25:
        raise ValueError(f"ML-DSA-65 keyGen vector coverage changed: {count}")
    return count


def run_siggen(library, prompt, expected):
    sign = bind(library, "deep_mldsa_v1_sign_from_seed", 5)
    count = 0
    deterministic = randomized = 0
    for group in prompt["testGroups"]:
        if group.get("parameterSet") != "ML-DSA-65":
            continue
        if not (group.get("testType") == "AFT" and group.get("keyFormat") == "seed"
                and group.get("signatureInterface") == "external"
                and group.get("preHash") == "pure"):
            continue
        cases = expected_by_id(expected, group["tgId"])
        for case in group["tests"]:
            seed = bytes.fromhex(case["seed"])
            random = bytes.fromhex(case["rnd"]) if "rnd" in case else bytes(32)
            context = bytes.fromhex(case["context"])
            message = bytes.fromhex(case["message"])
            reference = bytes.fromhex(cases[case["tcId"]]["signature"])
            if not (len(seed) == len(random) == 32 and len(context) <= 255
                    and len(message) <= 65535 and len(reference) == 3309):
                raise ValueError("ACVP signing vector is outside the Deep ABI")
            buffers = [input_buffer(item) for item in (seed, random, context, message)]
            signature = output_buffer(3309)
            arguments = [part for buffer, length in zip(buffers, (32, 32, len(context), len(message)))
                         for part in (buffer, length)]
            result = sign(*arguments, signature, 3309)
            if result != 0 or not hmac.compare_digest(signature.raw, reference):
                raise ValueError(f"Deep ABI sigGen failed ACVP tcId={case['tcId']}")
            count += 1
            if group["deterministic"]:
                deterministic += 1
            else:
                randomized += 1
    if (count, deterministic, randomized) != (30, 15, 15):
        raise ValueError(f"ML-DSA-65 sigGen vector coverage changed: {count}/{deterministic}/{randomized}")
    return count


def run_sigver(library, prompt, expected):
    verify = bind(library, "deep_mldsa_v1_verify", 4)
    count = positives = negatives = 0
    for group in prompt["testGroups"]:
        if group.get("parameterSet") != "ML-DSA-65":
            continue
        if not (group.get("testType") == "AFT"
                and group.get("signatureInterface") == "external"
                and group.get("preHash") == "pure"):
            continue
        cases = expected_by_id(expected, group["tgId"])
        for case in group["tests"]:
            public = bytes.fromhex(case["pk"])
            context = bytes.fromhex(case["context"])
            message = bytes.fromhex(case["message"])
            signature = bytes.fromhex(case["signature"])
            should_pass = cases[case["tcId"]]["testPassed"]
            if not (len(public) == 1952 and len(signature) == 3309
                    and len(context) <= 255 and len(message) <= 65535):
                raise ValueError("ACVP verification vector is outside the Deep ABI")
            buffers = [input_buffer(item) for item in (public, context, message, signature)]
            arguments = [part for buffer, length in zip(buffers,
                         (1952, len(context), len(message), 3309)) for part in (buffer, length)]
            result = verify(*arguments)
            if (result == 0) != should_pass or result not in (0, 4):
                raise ValueError(f"Deep ABI sigVer failed ACVP tcId={case['tcId']}")
            count += 1
            positives += bool(should_pass)
            negatives += not should_pass
    if count != 15 or positives == 0 or negatives == 0:
        raise ValueError(f"ML-DSA-65 sigVer vector coverage changed: {count}/{positives}/{negatives}")
    return count, positives, negatives


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--vectors-root", type=Path,
                        help="Use pre-downloaded official vectors; default fetches pinned files")
    args = parser.parse_args()
    documents = {name: load_vector(name, args.vectors_root) for name in PINS}
    library = ctypes.CDLL(str(args.library.resolve()))
    results = {}
    for kind in ("keyGen", "sigGen", "sigVer"):
        folder = f"ML-DSA-{kind}-FIPS204" + ("-tr1" if kind == "sigGen" else "")
        prompt = documents[f"{folder}/prompt.json"]
        expected = documents[f"{folder}/expectedResults.json"]
        if prompt["mode"] != kind or expected["mode"] != kind or prompt["vsId"] != expected["vsId"]:
            raise ValueError(f"Unexpected ACVP document pairing: {kind}")
        results[kind] = (prompt, expected)
    keygen = run_keygen(library, *results["keyGen"])
    siggen = run_siggen(library, *results["sigGen"])
    sigver, positives, negatives = run_sigver(library, *results["sigVer"])
    print(json.dumps({"schemaVersion": 1, "provider": "Deep.MlDsa/v1", "parameterSet": "ML-DSA-65",
                      "acvpVectorVersion": VERSION, "keyGenPassed": keygen, "sigGenPassed": siggen,
                      "sigVerPassed": sigver, "sigVerPositive": positives,
                      "sigVerNegative": negatives, "success": True}, separators=(",", ":")))


if __name__ == "__main__":
    main()
