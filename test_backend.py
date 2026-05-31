"""Headless end-to-end check of the vault backend (no GUI)."""

import json
import os
import tempfile

from vaultpm.store import AuthError, Vault, VaultError


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="vault-test-")
    path = os.path.join(tmp, "store.json")
    v = Vault(path)

    assert not v.exists(), "fresh vault must not exist yet"

    # init
    v.init("correct horse battery staple")
    assert v.exists() and v.unlocked
    print("[ok] init + unlocked")

    # add
    rec = v.add_item({"title": "GitHub", "username": "nasu",
                      "password": "p@ss-1", "url": "https://github.com",
                      "notes": "work account"})
    assert rec["id"] and rec["title"] == "GitHub"
    v.add_item({"title": "AWS", "username": "root", "password": "p@ss-2"})
    assert len(v.list_items()) == 2
    print("[ok] add + list")

    # title is required
    try:
        v.add_item({"title": "   "})
    except VaultError:
        print("[ok] empty title rejected")
    else:
        raise AssertionError("empty title should be rejected")

    # update
    v.update_item(rec["id"], {"password": "new-secret"})
    assert v.get_item(rec["id"])["password"] == "new-secret"
    print("[ok] update")

    # lock / wrong password / unlock
    v.lock()
    assert not v.unlocked
    try:
        v.unlock("WRONG")
    except AuthError:
        print("[ok] wrong password rejected")
    else:
        raise AssertionError("wrong password should fail")

    v.unlock("correct horse battery staple")
    assert len(v.list_items()) == 2
    assert v.get_item(rec["id"])["password"] == "new-secret"
    print("[ok] unlock + data persisted across lock")

    # change password
    v.change_password("correct horse battery staple", "brand new master")
    v.lock()
    try:
        v.unlock("correct horse battery staple")
    except AuthError:
        print("[ok] old password no longer works after re-key")
    else:
        raise AssertionError("old password should fail after change")
    v.unlock("brand new master")
    assert len(v.list_items()) == 2
    print("[ok] change_password re-encrypts and keeps data")

    # delete
    v.delete_item(rec["id"])
    assert len(v.list_items()) == 1
    print("[ok] delete")

    # tamper detection: flip a byte in the stored ciphertext
    import json
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    ct = raw["vault"]["ct"]
    raw["vault"]["ct"] = ("A" if ct[0] != "A" else "B") + ct[1:]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(raw, fh)
    v2 = Vault(path)
    try:
        v2.unlock("brand new master")
    except Exception:
        print("[ok] tampered ciphertext rejected (GCM auth)")
    else:
        raise AssertionError("tampering should be detected")

    print("\nALL BACKEND TESTS PASSED")


def test_pim() -> None:
    print("\n--- PIM (VeraCrypt-style) ---")
    tmp = tempfile.mkdtemp(prefix="vault-pim-")
    path = os.path.join(tmp, "store.json")

    v = Vault(path)
    v.init("master", pim=7)
    v.add_item({"title": "X", "password": "secret"})
    v.lock()

    # right password, wrong/empty PIM -> must fail (PIM is a real second factor)
    for bad in (0, 6, 8):
        try:
            v.unlock("master", pim=bad)
        except AuthError:
            pass
        else:
            raise AssertionError(f"unlock should fail with wrong PIM {bad}")
    print("[ok] wrong PIM rejected (0, 6, 8)")

    # right password + right PIM -> works
    v.unlock("master", pim=7)
    assert v.get_item(v.list_items()[0]["id"])["password"] == "secret"
    print("[ok] correct password + PIM unlocks")

    # iteration formula sanity
    from vaultpm import crypto
    assert crypto.iterations_for_pim(0) == 500000
    assert crypto.iterations_for_pim(7) == 15000 + 7 * 1000
    print("[ok] iterations: PIM0=500000, PIM7=22000")

    # change PIM, old PIM no longer valid
    v.change_password("master", "master", old_pim=7, new_pim=20)
    v.lock()
    try:
        v.unlock("master", pim=7)
    except AuthError:
        print("[ok] old PIM invalid after change")
    else:
        raise AssertionError("old PIM should fail after change")
    v.unlock("master", pim=20)
    assert len(v.list_items()) == 1
    print("[ok] new PIM works and data preserved")


def test_legacy_scrypt() -> None:
    print("\n--- legacy scrypt vault backward-compat ---")
    from vaultpm import crypto
    from vaultpm.store import VERIFY_TOKEN

    tmp = tempfile.mkdtemp(prefix="vault-legacy-")
    path = os.path.join(tmp, "store.json")

    # Hand-build an old-format scrypt vault (as v1.0 wrote them).
    salt = crypto.new_salt()
    key = crypto.derive_key("legacy-pw", salt)
    meta = {"algo": "scrypt", "n": crypto.SCRYPT_N, "r": crypto.SCRYPT_R,
            "p": crypto.SCRYPT_P, "salt": crypto.b64e(salt), "length": crypto.KEY_LEN}
    payload = json.dumps({"items": [{"id": "a1", "title": "Old", "username": "u",
                                     "password": "legacy-secret", "url": "", "notes": "",
                                     "created": "x", "updated": "x"}]}).encode()
    data = {"version": 1, "kdf": meta,
            "verifier": crypto.encrypt(key, VERIFY_TOKEN),
            "vault": crypto.encrypt(key, payload)}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)

    v = Vault(path)
    v.unlock("legacy-pw")  # PIM ignored for scrypt vaults
    assert v.get_item("a1")["password"] == "legacy-secret"
    print("[ok] legacy scrypt vault still unlocks (password only)")

    # migrate to pbkdf2 + PIM via change_password
    v.change_password("legacy-pw", "legacy-pw", old_pim=0, new_pim=3)
    v.lock()
    assert json.load(open(path))["kdf"]["algo"] == "pbkdf2-sha512"
    v.unlock("legacy-pw", pim=3)
    assert v.get_item("a1")["password"] == "legacy-secret"
    print("[ok] migrated scrypt -> pbkdf2+PIM, data preserved")


if __name__ == "__main__":
    main()
    test_pim()
    test_legacy_scrypt()
    print("\nALL EXTENDED TESTS PASSED")
