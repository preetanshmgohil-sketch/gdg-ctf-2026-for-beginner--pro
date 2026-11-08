"""
A deliberately small ECDSA implementation over secp256k1.

This file exists so the challenge can demonstrate a nonce-reuse flaw without
depending on a crypto library that would make the flaw impossible to model.
It is not constant-time and is not suitable for real cryptography.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

Point = Optional[tuple[int, int]]


def mod_inv(value: int, modulus: int) -> int:
    """Modular inverse via Fermat's little theorem (modulus is prime)."""
    if value % modulus == 0:
        raise ZeroDivisionError("inverse of zero")
    return pow(value, modulus - 2, modulus)


def point_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p

    x1, y1 = p
    x2, y2 = q

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if p == q:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1 + A) * mod_inv(2 * y1, P) % P
    else:
        slope = (y2 - y1) * mod_inv(x2 - x1, P) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_mul(scalar: int, point: Point = G) -> Point:
    if scalar % N == 0 or point is None:
        return None

    result: Point = None
    addend: Point = point
    k = scalar % N
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def hash_message(message: str) -> int:
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % N


def public_key(private_key: int) -> tuple[int, int]:
    point = point_mul(private_key)
    if point is None:
        raise ValueError("invalid private key")
    return point


def sign(private_key: int, message: str, nonce: int) -> tuple[int, int, int]:
    """Return (r, s, z). The caller is responsible for choosing the nonce."""
    if not 1 <= nonce < N:
        raise ValueError("nonce out of range")

    z = hash_message(message)
    point = point_mul(nonce)
    if point is None:
        raise ValueError("invalid nonce")
    r = point[0] % N
    if r == 0:
        raise ValueError("bad nonce: r == 0")

    s = (mod_inv(nonce, N) * (z + r * private_key)) % N
    if s == 0:
        raise ValueError("bad nonce: s == 0")
    return r, s, z


def verify(public: tuple[int, int], message: str, r: int, s: int) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False

    z = hash_message(message)
    w = mod_inv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = point_add(point_mul(u1), point_mul(u2, public))
    if point is None:
        return False
    return point[0] % N == r


@dataclass(frozen=True)
class Signature:
    r: int
    s: int
    z: int
