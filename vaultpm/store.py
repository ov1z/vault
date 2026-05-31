"""Encrypted vault storage.

On-disk layout (a single JSON file):

    {
      "version": 1,
      "kdf":      {"algo": "scrypt", "n", "r", "p", "salt", "length"},
      "verifier": {"nonce", "ct"},   # encrypts a known token -> password check
      "vault":    {"nonce", "ct"}    # encrypts json({"items": [...]})
    }

The whole item list is encrypted as one blob, so titles, URLs and notes are
never written in clear text. The master key lives only in memory while the
vault is unlocked.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import datetime

from . import crypto

VERIFY_TOKEN = b"vault-verify-v1"
STORE_VERSION = 1

ITEM_FIELDS = ("title", "username", "password", "url", "notes", "totp")


class VaultError(Exception):
    """Generic vault failure."""


class LockedError(VaultError):
    """Raised when an operation needs an unlocked vault."""


class AuthError(VaultError):
    """Raised on a wrong master password."""


def default_store_path() -> str:
    base = os.environ.get("VAULT_HOME") or os.path.join(os.path.expanduser("~"), ".vault")
    return os.path.join(base, "store.json")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Vault:
    def __init__(self, path: str | None = None):
        self.path = path or default_store_path()
        self._key: bytes | None = None
        self._items: list[dict] | None = None
        self._meta: dict | None = None  # kdf parameters

    # -- state ---------------------------------------------------------------

    def exists(self) -> bool:
        return os.path.exists(self.path)

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def _require_unlocked(self) -> None:
        if not self.unlocked:
            raise LockedError("Vault is locked")

    # -- key derivation ------------------------------------------------------

    @staticmethod
    def _new_pbkdf2_meta(salt: bytes) -> dict:
        """KDF header for a new vault. Records the (public) PIM formula
        constants so the file is self-describing, but never the PIM itself."""
        return {
            "algo": "pbkdf2-sha512",
            "salt": crypto.b64e(salt),
            "length": crypto.KEY_LEN,
            "iter_base": crypto.PIM_ITER_BASE,
            "iter_mult": crypto.PIM_ITER_MULT,
            "iter_default": crypto.DEFAULT_ITERATIONS,
        }

    @staticmethod
    def _derive_with(password: str, meta: dict, pim: int) -> bytes:
        """Derive the master key for a given KDF header + PIM.

        For legacy scrypt vaults the PIM is ignored (they predate it)."""
        salt = crypto.b64d(meta["salt"])
        if meta.get("algo") == "pbkdf2-sha512":
            iterations = crypto.iterations_for_pim(
                pim,
                base=meta.get("iter_base", crypto.PIM_ITER_BASE),
                mult=meta.get("iter_mult", crypto.PIM_ITER_MULT),
                default=meta.get("iter_default", crypto.DEFAULT_ITERATIONS),
            )
            return crypto.derive_key_pbkdf2(password, salt, iterations)
        # legacy scrypt
        return crypto.derive_key(password, salt,
                                 n=meta["n"], r=meta["r"], p=meta["p"])

    # -- lifecycle -----------------------------------------------------------

    def init(self, password: str, pim: int = 0) -> None:
        """Create a brand new, empty vault (pbkdf2 + PIM) and leave it unlocked."""
        if not password:
            raise VaultError("Master password must not be empty")
        if self.exists():
            raise VaultError("A vault already exists at this location")
        salt = crypto.new_salt()
        self._meta = self._new_pbkdf2_meta(salt)
        self._key = self._derive_with(password, self._meta, pim)
        self._items = []
        self._write()

    def unlock(self, password: str, pim: int = 0) -> bool:
        """Verify password (+ PIM) and load + decrypt the item list."""
        data = self._read_raw()
        kdf = data["kdf"]
        key = self._derive_with(password, kdf, pim)
        try:
            token = crypto.decrypt(key, data["verifier"])
        except Exception:
            raise AuthError("Wrong master password or PIM")
        if token != VERIFY_TOKEN:
            raise AuthError("Wrong master password or PIM")

        payload = json.loads(crypto.decrypt(key, data["vault"]).decode("utf-8"))
        self._key = key
        self._meta = kdf
        self._items = payload.get("items", [])
        return True

    def lock(self) -> None:
        self._key = None
        self._items = None

    def change_password(self, old_password: str, new_password: str,
                        old_pim: int = 0, new_pim: int = 0) -> bool:
        """Re-key the vault. Always migrates to pbkdf2 + the chosen new PIM."""
        self._require_unlocked()
        if not new_password:
            raise VaultError("New master password must not be empty")
        check = self._derive_with(old_password, self._meta, old_pim)
        if check != self._key:
            raise AuthError("Current password or PIM is incorrect")
        salt = crypto.new_salt()
        self._meta = self._new_pbkdf2_meta(salt)
        self._key = self._derive_with(new_password, self._meta, new_pim)
        self._write()
        return True

    # -- items ---------------------------------------------------------------

    def list_items(self) -> list[dict]:
        self._require_unlocked()
        items = [dict(i) for i in self._items]
        items.sort(key=lambda x: (x.get("title") or "").lower())
        return items

    def get_item(self, item_id: str) -> dict:
        self._require_unlocked()
        for rec in self._items:
            if rec["id"] == item_id:
                return dict(rec)
        raise VaultError("Item not found")

    def add_item(self, data: dict) -> dict:
        self._require_unlocked()
        title = (data.get("title") or "").strip()
        if not title:
            raise VaultError("Title is required")
        rec = {"id": secrets.token_hex(8), "created": _now(), "updated": _now()}
        for field in ITEM_FIELDS:
            rec[field] = (data.get(field) or "")
        rec["title"] = title
        self._items.append(rec)
        self._write()
        return rec

    def update_item(self, item_id: str, data: dict) -> dict:
        self._require_unlocked()
        for rec in self._items:
            if rec["id"] == item_id:
                for field in ITEM_FIELDS:
                    if field in data:
                        rec[field] = data[field] or ""
                rec["title"] = (rec.get("title") or "").strip() or rec["title"]
                rec["updated"] = _now()
                self._write()
                return dict(rec)
        raise VaultError("Item not found")

    def delete_item(self, item_id: str) -> bool:
        self._require_unlocked()
        before = len(self._items)
        self._items = [i for i in self._items if i["id"] != item_id]
        if len(self._items) == before:
            raise VaultError("Item not found")
        self._write()
        return True

    # -- persistence ---------------------------------------------------------

    def _read_raw(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write(self) -> None:
        assert self._key is not None and self._items is not None and self._meta is not None
        payload = json.dumps({"items": self._items}).encode("utf-8")
        data = {
            "version": STORE_VERSION,
            "kdf": self._meta,
            "verifier": crypto.encrypt(self._key, VERIFY_TOKEN),
            "vault": crypto.encrypt(self._key, payload),
        }
        directory = os.path.dirname(self.path)
        os.makedirs(directory, exist_ok=True)

        # Atomic write: temp file in the same directory, then os.replace.
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

        # Best-effort permission hardening on POSIX (no-op on Windows).
        try:
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        except OSError:
            pass
