"""Cryptographic primitives for the vault.

Key derivation:
  * pbkdf2-sha512 with a VeraCrypt-style PIM (Personal Iterations Multiplier)
    for vaults created from v1.1 onwards.
  * scrypt (N=2^15, r=8, p=1) -- legacy vaults, still readable.
Encryption:
  * AES-256-GCM (authenticated) with a fresh 96-bit nonce per blob.

Nothing here rolls its own crypto -- it only orchestrates well-vetted
primitives from `cryptography` and the standard library (hashlib.pbkdf2_hmac,
which is the OpenSSL implementation).
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ---- PBKDF2 / PIM (VeraCrypt non-system-volume scheme) ---------------------
# Iterations are derived from the PIM, mirroring VeraCrypt:
#   PIM == 0 (unset) -> DEFAULT_ITERATIONS
#   PIM  > 0         -> PIM_ITER_BASE + PIM * PIM_ITER_MULT
# The PIM itself is a SECRET second factor and is never written to disk.
PBKDF2_HASH = "sha512"
PIM_ITER_BASE = 15000
PIM_ITER_MULT = 1000
DEFAULT_ITERATIONS = 500000


def iterations_for_pim(pim: int, *, base: int = PIM_ITER_BASE,
                       mult: int = PIM_ITER_MULT,
                       default: int = DEFAULT_ITERATIONS) -> int:
    pim = max(0, int(pim or 0))
    return default if pim == 0 else base + pim * mult


def derive_key_pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a 256-bit key with PBKDF2-HMAC-SHA512 (OpenSSL)."""
    return hashlib.pbkdf2_hmac(PBKDF2_HASH, password.encode("utf-8"),
                               salt, iterations, dklen=KEY_LEN)


# scrypt cost parameters. N must be a power of two.
SCRYPT_N = 2 ** 15  # ~32 MB working set, ~0.1-0.2s on a modern CPU
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32         # 256-bit key -> AES-256
SALT_LEN = 16
NONCE_LEN = 12       # 96-bit nonce, the GCM standard


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: str, salt: bytes,
               n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    """Derive a 256-bit key from a password using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes) -> dict:
    """Encrypt with AES-256-GCM. Returns a JSON-serialisable {nonce, ct} dict."""
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return {"nonce": b64e(nonce), "ct": b64e(ct)}


def decrypt(key: bytes, blob: dict) -> bytes:
    """Decrypt an {nonce, ct} dict. Raises if the key is wrong or data tampered."""
    return AESGCM(key).decrypt(b64d(blob["nonce"]), b64d(blob["ct"]), None)
