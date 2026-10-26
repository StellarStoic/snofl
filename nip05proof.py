"""BIP-340 Schnorr signatures, in the standard library only.

The NIP-05 registration route needs to know that whoever asks for `name@snofl.com` holds the private key
for the pubkey they are attaching to it. A signature is the only honest proof of that, and the app has no
crypto dependency on the server side — so verification lives here, in pure Python, and is proven against
the official BIP-340 test vectors (see `--self-test`) rather than against my own arithmetic.

Nothing here is performance-critical: one verification per registration, a few milliseconds.
"""

from __future__ import annotations

import hashlib
import re

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def _tagged_hash(tag: str, payload: bytes) -> bytes:
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + payload).digest()


def _inv(a: int) -> int:
    return pow(a, P - 2, P)


def _point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _point_mul(point, scalar: int):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _lift_x(x: int):
    """The even-y point with this x, or None if it is not on the curve."""
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def schnorr_verify(msg: bytes, pubkey: bytes, signature: bytes) -> bool:
    """Verify a BIP-340 signature.

    The message may be any length — the spec hashes `r || pk || msg` inside the challenge, and the
    official vectors include messages of 0, 1, 17 and 100 bytes. A caller with a 32-byte digest (which
    is what a registration proof is) is just the common case.
    """
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    point = _lift_x(int.from_bytes(pubkey, "big"))
    if point is None:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", signature[:32] + pubkey + msg), "big") % N
    # R = s*G - e*P
    neg_e_p = _point_mul(point, (N - e) % N)
    big_r = _point_add(_point_mul(G, s), neg_e_p)
    if big_r is None or big_r[1] % 2 != 0 or big_r[0] != r:
        return False
    return True


def schnorr_sign(msg: bytes, seckey: bytes, aux: bytes = b"\x00" * 32) -> bytes:
    """Sign a message of any length. Used by the tests and the live check, not by the app."""
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 <= N - 1:
        raise ValueError("secret key out of range")
    pub = _point_mul(G, d0)
    if pub is None:  # unreachable: d0 is non-zero and below the group order
        raise ValueError("public key is at infinity")
    d = d0 if pub[1] % 2 == 0 else N - d0
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), _tagged_hash("BIP0340/aux", aux)))
    rand = _tagged_hash("BIP0340/nonce", t + pub[0].to_bytes(32, "big") + msg)
    k0 = int.from_bytes(rand, "big") % N
    if k0 == 0:
        raise ValueError("nonce is zero")
    big_r = _point_mul(G, k0)
    if big_r is None:  # unreachable: k0 is non-zero and in range
        raise ValueError("nonce point is at infinity")
    k = k0 if big_r[1] % 2 == 0 else N - k0
    e = int.from_bytes(
        _tagged_hash("BIP0340/challenge",
                     big_r[0].to_bytes(32, "big") + pub[0].to_bytes(32, "big") + msg), "big") % N
    sig = big_r[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")
    assert schnorr_verify(msg, pub[0].to_bytes(32, "big"), sig)
    return sig


# --------------------------------------------------------------------------------------------------
# What the site signs: a NIP-05 name is a promise about a pubkey, so the proof names both, plus a
# timestamp so a proof cannot be replayed for ever.
# --------------------------------------------------------------------------------------------------

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
PUBKEY_RE = re.compile(r"^[0-9a-f]{64}$")


def registration_message(name: str, pubkey: str, created_at: int) -> bytes:
    """The 32-byte message a client signs to claim `name` for `pubkey`."""
    return hashlib.sha256(f"snofl-nip05:{name}:{pubkey}:{int(created_at)}".encode()).digest()


def validate_name(name) -> str | None:
    """Return an error string, or None when the name is acceptable.

    The name becomes a filename for the LNURLP record, which is how a request body reached
    `os.path.join(LNURLP_DIR, name)` and could walk out of the directory with `../`. A strict
    character class is the fix: no separators, no dots at the edges, no empty name, and `_` stays
    reserved because it is the domain's own NIP-05 root name.
    """
    if not isinstance(name, str) or not name:
        return "a name is required"
    if name == "_":
        return "'_' is reserved for the domain itself"
    if not NAME_RE.match(name):
        return ("a name may only use a-z, 0-9, dot, underscore and hyphen, must start with a letter "
                "or digit, and be at most 63 characters")
    return None


def verify_proof(name: str, pubkey: str, proof, now: int, max_age: int = 600) -> str | None:
    """Check one name→pubkey claim. Returns an error string, or None when the proof is good."""
    if not PUBKEY_RE.match(pubkey or ""):
        return "a pubkey must be 64 lowercase hex characters"
    if not isinstance(proof, dict):
        return "a proof is required for each name"
    signature = (proof.get("sig") or "").lower()
    if not re.match(r"^[0-9a-f]{128}$", signature):
        return "the signature must be 128 hex characters"
    raw_created = proof.get("created_at")
    if raw_created is None:
        return "the proof needs a created_at timestamp"
    try:
        created_at = int(raw_created)
    except (TypeError, ValueError):
        return "the proof needs a created_at timestamp"
    if abs(now - created_at) > max_age:
        return "the proof is older than %d seconds — sign a fresh one" % max_age
    if proof.get("name") != name or (proof.get("pubkey") or "").lower() != pubkey:
        return "the proof must name the same name and pubkey it claims"
    message = registration_message(name, pubkey, created_at)
    if not schnorr_verify(message, bytes.fromhex(pubkey), bytes.fromhex(signature)):
        return "the signature does not verify against that pubkey"
    return None


def _self_test(vectors_csv: str) -> int:
    """Run the official BIP-340 vectors: every 'TRUE' must verify, every 'FALSE' must not."""
    import csv
    passed = failed = 0
    with open(vectors_csv, newline="") as handle:
        for row in csv.DictReader(handle):
            if not row.get("message"):
                continue
            msg = bytes.fromhex(row["message"])
            pub = bytes.fromhex(row["public key"])
            sig = bytes.fromhex(row["signature"])
            expected = row["verification result"].strip().upper() == "TRUE"
            got = schnorr_verify(msg, pub, sig)
            if got == expected:
                passed += 1
            else:
                failed += 1
                print("  MISMATCH vector %s: expected %s, got %s" % (row["index"], expected, got))
    print("  vectors passed: %d | failed: %d" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    import sys
    sys.exit(_self_test(sys.argv[1] if len(sys.argv) > 1 else "bip340-vectors.csv"))
