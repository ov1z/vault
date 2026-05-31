"""Open the real WebView window briefly and assert the UI + bridge load.

Uses a throwaway VAULT_HOME so it never touches a real vault. The window
appears for a couple of seconds, runs assertions via evaluate_js, then closes.
"""

import os
import tempfile
import time

# Sandbox the vault location BEFORE importing the app.
TMP = tempfile.mkdtemp(prefix="vault-smoke-")
os.environ["VAULT_HOME"] = TMP

import webview

from vaultpm.api import Api
from vaultpm.app import resource_dir
from vaultpm.store import Vault

results = {}


BRIDGE_FLOW = """
window.__done = false;
(async () => {
  const api = window.pywebview.api;
  try {
    const g = await api.generate_password({length: 18, symbols: true});
    const init = await api.init_vault('smoke-master-pw', 7);   // PIM = 7
    const add = await api.add_item({title: 'GH', username: 'u', password: 'p@1', totp: 'JBSWY3DPEHPK3PXP'});
    const list = await api.list_items();
    const tc = await api.totp_code(add.item.id);
    const chk = await api.totp_check('JBSWY3DPEHPK3PXP');
    await api.lock();
    const wrongPim = await api.unlock('smoke-master-pw', 0);   // wrong PIM -> fail
    const rightPim = await api.unlock('smoke-master-pw', 7);   // right PIM -> ok
    const list2 = await api.list_items();

    // --- security: malicious URL must NOT become a clickable link ---
    const mal = await api.add_item({title: 'mal', url: 'javascript:alert(document.cookie)', password: 'x'});
    const safe = await api.add_item({title: 'safe', url: 'https://example.com/login', password: 'y'});
    await selectItem(mal.item.id);
    const malAnchors = [...document.querySelectorAll('#detail-body a')].length;
    await selectItem(safe.item.id);
    const safeAnchors = [...document.querySelectorAll('#detail-body a')];
    const safeHref = safeAnchors.length ? (safeAnchors[0].getAttribute('href') || '') : '';

    window.__result = JSON.stringify({
      gen_len: g.ok ? g.password.length : -1,
      init_ok: init.ok, add_ok: add.ok, count: list.items.length,
      has_totp: list.items[0] ? list.items[0].has_totp : null,
      totp_len: tc.ok ? tc.code.length : -1,
      totp_check: chk.ok,
      pim_wrong_ok: wrongPim.ok, pim_right_ok: rightPim.ok,
      count2: list2.ok ? list2.items.length : -1,
      mal_anchor_count: malAnchors,
      safe_anchor_https: safeAnchors.length === 1 && safeHref.indexOf('https://') === 0,
      safeurl_blocks: (typeof safeUrl === 'function')
        && safeUrl('javascript:x') === null && !!safeUrl('https://x'),
      csp_present: !!document.querySelector('meta[http-equiv="Content-Security-Policy"]')
    });
  } catch (e) { window.__result = 'ERR:' + e; }
  window.__done = true;
})();
"""


def worker(window):
    time.sleep(3.0)  # allow the page + WebView2 to finish loading
    try:
        results["title"] = window.evaluate_js("document.title")
        results["gate_visible"] = window.evaluate_js(
            "!document.getElementById('gate').classList.contains('hidden')")
        results["setup_visible"] = window.evaluate_js(
            "!document.getElementById('setup-form').classList.contains('hidden')")
        results["has_bridge"] = window.evaluate_js(
            "typeof window.pywebview !== 'undefined' && !!window.pywebview.api")
        results["css_loaded"] = window.evaluate_js(
            "getComputedStyle(document.body).backgroundColor")
        results["icons_painted"] = window.evaluate_js(
            "!!document.querySelector('[data-ic]') && "
            "!!document.querySelector('[data-ic] svg')")

        # Real async bridge round-trip: JS -> Python -> JS, the path the UI uses.
        window.evaluate_js(BRIDGE_FLOW)
        for _ in range(20):
            if window.evaluate_js("window.__done === true"):
                break
            time.sleep(0.25)
        results["bridge_flow"] = window.evaluate_js("window.__result")
    except Exception as exc:  # noqa: BLE001
        results["error"] = repr(exc)
    finally:
        window.destroy()


def main():
    api = Api(Vault(os.path.join(TMP, "store.json")))
    index = os.path.join(resource_dir(), "index.html")
    window = webview.create_window("Vault (smoke)", url=index, js_api=api,
                                   width=1000, height=680)
    webview.start(worker, window)

    print("Smoke results:")
    for k, v in results.items():
        print(f"  {k}: {v}")

    import json
    flow = {}
    try:
        flow = json.loads(results.get("bridge_flow") or "{}")
    except (ValueError, TypeError):
        pass

    ok = (results.get("title") == "Vault"
          and results.get("gate_visible") is True
          and results.get("setup_visible") is True
          and results.get("has_bridge") is True
          and results.get("icons_painted") is True
          and results.get("css_loaded") == "rgb(13, 13, 15)"
          and flow.get("gen_len") == 18
          and flow.get("init_ok") is True
          and flow.get("add_ok") is True
          and flow.get("count") == 1
          and flow.get("has_totp") is True
          and flow.get("totp_len") == 6
          and flow.get("totp_check") is True
          and flow.get("pim_wrong_ok") is False
          and flow.get("pim_right_ok") is True
          and flow.get("count2") == 1
          and flow.get("mal_anchor_count") == 0
          and flow.get("safe_anchor_https") is True
          and flow.get("safeurl_blocks") is True
          and flow.get("csp_present") is True
          and "error" not in results)
    print("\nGUI SMOKE:", "PASS" if ok else "FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
