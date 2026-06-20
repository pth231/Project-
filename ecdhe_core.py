from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


def require_cryptography():
    try:
        import cryptography
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except Exception as exc:
        raise RuntimeError(
            "This ECDHE helper requires pyca/cryptography. Install it with:\n"
            "  python -m pip install cryptography"
        ) from exc

    return {
        "cryptography": cryptography,
        "hashes": hashes,
        "serialization": serialization,
        "ec": ec,
        "x25519": x25519,
        "x448": x448,
        "HKDF": HKDF,
    }


FAMILY_EC = "short-weierstrass-ecdh"
FAMILY_X25519 = "x25519"
FAMILY_X448 = "x448"


@dataclass(frozen=True)
class ECDHEGroup:
    name: str
    aliases: Tuple[str, ...]
    family: str
    bits: int
    security_bits: int
    openssl_name: str
    equation: str
    generator_note: str
    kdf_hash: str
    description: str


GROUPS = (
    ECDHEGroup(
        name="secp256r1",
        aliases=("p-256", "p256", "prime256v1", "nistp256", "nist-p256"),
        family=FAMILY_EC,
        bits=256,
        security_bits=128,
        openssl_name="secp256r1",
        equation="y^2 = x^3 - 3*x + b over F_p",
        generator_note="Generator G is the standard NIST P-256 base point.",
        kdf_hash="sha256",
        description="NIST P-256 / prime256v1 short-Weierstrass ECDHE group.",
    ),
    ECDHEGroup(
        name="secp384r1",
        aliases=("p-384", "p384", "nistp384", "nist-p384"),
        family=FAMILY_EC,
        bits=384,
        security_bits=192,
        openssl_name="secp384r1",
        equation="y^2 = x^3 - 3*x + b over F_p",
        generator_note="Generator G is the standard NIST P-384 base point.",
        kdf_hash="sha384",
        description="NIST P-384 short-Weierstrass ECDHE group.",
    ),
    ECDHEGroup(
        name="secp521r1",
        aliases=("p-521", "p521", "nistp521", "nist-p521"),
        family=FAMILY_EC,
        bits=521,
        security_bits=256,
        openssl_name="secp521r1",
        equation="y^2 = x^3 - 3*x + b over F_p",
        generator_note="Generator G is the standard NIST P-521 base point.",
        kdf_hash="sha512",
        description="NIST P-521 short-Weierstrass ECDHE group.",
    ),
    ECDHEGroup(
        name="secp256k1",
        aliases=("k-256", "k256", "bitcoin"),
        family=FAMILY_EC,
        bits=256,
        security_bits=128,
        openssl_name="secp256k1",
        equation="y^2 = x^3 + 7 over F_p",
        generator_note="Generator G is the SEC2 secp256k1 base point.",
        kdf_hash="sha256",
        description="Koblitz-style short-Weierstrass curve used by Bitcoin; not a common TLS ECDHE default.",
    ),
    ECDHEGroup(
        name="x25519",
        aliases=("curve25519", "curve-25519", "montgomery25519"),
        family=FAMILY_X25519,
        bits=255,
        security_bits=128,
        openssl_name="X25519",
        equation="v^2 = u^3 + 486662*u^2 + u over F_p, p = 2^255 - 19",
        generator_note="X25519 uses the Montgomery u-coordinate base point u = 9.",
        kdf_hash="sha256",
        description="Montgomery XDH group. Public keys are 32-byte u-coordinates.",
    ),
    ECDHEGroup(
        name="x448",
        aliases=("curve448", "curve-448", "montgomery448"),
        family=FAMILY_X448,
        bits=448,
        security_bits=224,
        openssl_name="X448",
        equation="v^2 = u^3 + 156326*u^2 + u over F_p, p = 2^448 - 2^224 - 1",
        generator_note="X448 uses the Montgomery u-coordinate base point u = 5.",
        kdf_hash="sha512",
        description="Montgomery XDH group. Public keys are 56-byte u-coordinates.",
    ),
)


def _key(text: str) -> str:
    return text.strip().lower().replace("_", "-")


GROUP_LOOKUP: Dict[str, ECDHEGroup] = {}
for group in GROUPS:
    GROUP_LOOKUP[_key(group.name)] = group
    for alias in group.aliases:
        GROUP_LOOKUP[_key(alias)] = group


def ec_curve_object(group: ECDHEGroup):
    d = require_cryptography()
    ec = d["ec"]
    mapping = {
        "secp256r1": ec.SECP256R1,
        "secp384r1": ec.SECP384R1,
        "secp521r1": ec.SECP521R1,
        "secp256k1": ec.SECP256K1,
    }
    try:
        return mapping[group.openssl_name]()
    except KeyError as exc:
        raise RuntimeError(f"no EC curve mapping for {group.name}") from exc


def generate_private_key(group: ECDHEGroup):
    d = require_cryptography()
    if group.family == FAMILY_EC:
        return d["ec"].generate_private_key(ec_curve_object(group))
    if group.family == FAMILY_X25519:
        return d["x25519"].X25519PrivateKey.generate()
    if group.family == FAMILY_X448:
        return d["x448"].X448PrivateKey.generate()
    raise RuntimeError(f"unsupported group family {group.family}")


def load_raw_public_key(data: bytes, group: ECDHEGroup):
    d = require_cryptography()
    ec = d["ec"]
    x25519 = d["x25519"]
    x448 = d["x448"]

    if group.family == FAMILY_EC:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec_curve_object(group), data)
    if group.family == FAMILY_X25519:
        return x25519.X25519PublicKey.from_public_bytes(data)
    if group.family == FAMILY_X448:
        return x448.X448PublicKey.from_public_bytes(data)
    raise RuntimeError(f"unsupported group family {group.family}")


def ecdh_exchange(private_key, peer_public_key, group: ECDHEGroup) -> bytes:
    if group.family == FAMILY_EC:
        ec = require_cryptography()["ec"]
        return private_key.exchange(ec.ECDH(), peer_public_key)
    if group.family in {FAMILY_X25519, FAMILY_X448}:
        return private_key.exchange(peer_public_key)
    raise RuntimeError(f"unsupported group family {group.family}")


def hash_algorithm(name: str, group: ECDHEGroup):
    hashes = require_cryptography()["hashes"]
    normalized = group.kdf_hash if name == "auto" else name.lower().replace("-", "")
    if normalized == "sha256":
        return hashes.SHA256()
    if normalized == "sha384":
        return hashes.SHA384()
    if normalized == "sha512":
        return hashes.SHA512()
    raise ValueError("supported hashes: auto, sha256, sha384, sha512")


def hkdf_derive(
    shared_secret: bytes,
    group: ECDHEGroup,
    *,
    key_len: int,
    hash_name: str,
    salt: bytes | None,
    info: bytes,
) -> bytes:
    HKDF = require_cryptography()["HKDF"]
    return HKDF(
        algorithm=hash_algorithm(hash_name, group),
        length=key_len,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def public_key_to_raw(public_key, group: ECDHEGroup) -> bytes:
    d = require_cryptography()
    serialization = d["serialization"]
    ec = d["ec"]

    if group.family == FAMILY_EC:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("expected EC public key")
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
