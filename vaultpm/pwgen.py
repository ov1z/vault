"""Cryptographically-secure password generator."""

from __future__ import annotations

import secrets
import string

# Characters easily confused with one another, optionally excluded.
AMBIGUOUS = set("Il1O0o`'\"")

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


def generate_password(length: int = 20, *, lowercase: bool = True,
                      uppercase: bool = True, digits: bool = True,
                      symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    """Return a random password drawn from the selected character classes.

    Guarantees at least one character from every selected class.
    """
    pools: list[str] = []
    if lowercase:
        pools.append(string.ascii_lowercase)
    if uppercase:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:  # fall back to alphanumeric if caller disabled everything
        pools.append(string.ascii_letters + string.digits)

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]
        pools = [p for p in pools if p]

    alphabet = "".join(pools)
    length = max(4, min(int(length), 128))

    # Reject samples that miss a required class. With realistic lengths this
    # almost never loops more than once.
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw
