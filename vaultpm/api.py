"""The object exposed to the web UI as `window.pywebview.api`.

Every method returns a JSON-serialisable dict shaped like
``{"ok": True, ...}`` or ``{"ok": False, "error": "..."}`` so the front-end
never has to rely on exception propagation across the bridge.
"""

from __future__ import annotations

from . import clipboard, pwgen, totp
from .store import AuthError, LockedError, Vault, VaultError


def _pim(value) -> int:
    """Coerce a PIM value from the UI (string/None/number) to a non-negative int."""
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError):
        return 0


def _ok(**kwargs) -> dict:
    return {"ok": True, **kwargs}


def _err(message: str) -> dict:
    return {"ok": False, "error": message}


def _safe_item(rec: dict) -> dict:
    """Item metadata for list rendering -- omits the password."""
    return {
        "id": rec["id"],
        "title": rec.get("title", ""),
        "username": rec.get("username", ""),
        "url": rec.get("url", ""),
        "updated": rec.get("updated", ""),
        "has_totp": bool((rec.get("totp") or "").strip()),
    }


class Api:
    def __init__(self, vault: Vault | None = None):
        self.vault = vault or Vault()

    # -- status / lifecycle --------------------------------------------------

    def status(self) -> dict:
        return _ok(initialized=self.vault.exists(), unlocked=self.vault.unlocked)

    def init_vault(self, password: str, pim: int = 0) -> dict:
        try:
            self.vault.init(password, _pim(pim))
            return _ok()
        except VaultError as exc:
            return _err(str(exc))

    def unlock(self, password: str, pim: int = 0) -> dict:
        try:
            self.vault.unlock(password, _pim(pim))
            return _ok()
        except AuthError as exc:
            return _err(str(exc))
        except (OSError, ValueError, KeyError) as exc:
            return _err(f"Could not read vault: {exc}")

    def lock(self) -> dict:
        self.vault.lock()
        return _ok()

    def change_password(self, old_password: str, new_password: str,
                        old_pim: int = 0, new_pim: int = 0) -> dict:
        try:
            self.vault.change_password(old_password, new_password,
                                       _pim(old_pim), _pim(new_pim))
            return _ok()
        except (AuthError, LockedError, VaultError) as exc:
            return _err(str(exc))

    # -- items ---------------------------------------------------------------

    def list_items(self) -> dict:
        try:
            items = [_safe_item(i) for i in self.vault.list_items()]
            return _ok(items=items)
        except LockedError as exc:
            return _err(str(exc))

    def get_item(self, item_id: str) -> dict:
        try:
            return _ok(item=self.vault.get_item(item_id))
        except (LockedError, VaultError) as exc:
            return _err(str(exc))

    def add_item(self, data: dict) -> dict:
        try:
            return _ok(item=_safe_item(self.vault.add_item(data)))
        except (LockedError, VaultError) as exc:
            return _err(str(exc))

    def update_item(self, item_id: str, data: dict) -> dict:
        try:
            return _ok(item=_safe_item(self.vault.update_item(item_id, data)))
        except (LockedError, VaultError) as exc:
            return _err(str(exc))

    def delete_item(self, item_id: str) -> dict:
        try:
            self.vault.delete_item(item_id)
            return _ok()
        except (LockedError, VaultError) as exc:
            return _err(str(exc))

    # -- helpers -------------------------------------------------------------

    def generate_password(self, opts: dict | None = None) -> dict:
        opts = opts or {}
        try:
            pw = pwgen.generate_password(
                length=int(opts.get("length", 20)),
                lowercase=bool(opts.get("lowercase", True)),
                uppercase=bool(opts.get("uppercase", True)),
                digits=bool(opts.get("digits", True)),
                symbols=bool(opts.get("symbols", True)),
                avoid_ambiguous=bool(opts.get("avoid_ambiguous", False)),
            )
            return _ok(password=pw)
        except (ValueError, TypeError) as exc:
            return _err(str(exc))

    def totp_code(self, item_id: str) -> dict:
        """Current one-time code for an item that has a stored TOTP secret."""
        try:
            item = self.vault.get_item(item_id)
        except (LockedError, VaultError) as exc:
            return _err(str(exc))
        secret = (item.get("totp") or "").strip()
        if not secret:
            return _err("no totp secret")
        try:
            return _ok(**totp.code(secret))
        except totp.TOTPError as exc:
            return _err(str(exc))

    def totp_check(self, secret: str) -> dict:
        """Validate a secret/URI as the user types it in the editor."""
        try:
            c = totp.code(secret)
            return _ok(code=c["code"])
        except totp.TOTPError as exc:
            return _err(str(exc))

    def copy_clipboard(self, text: str) -> dict:
        try:
            clipboard.copy(text or "")
            return _ok()
        except OSError as exc:
            return _err(str(exc))
