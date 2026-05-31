"""Application entry point: opens the native WebView window."""

from __future__ import annotations

import os
import sys

import webview

from .api import Api


def resource_dir() -> str:
    """Directory holding the bundled web assets, in dev and PyInstaller builds."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:  # frozen by PyInstaller (web added via --add-data)
        return os.path.join(meipass, "web")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def main() -> None:
    api = Api()
    index = os.path.join(resource_dir(), "index.html")
    webview.create_window(
        "Vault",
        url=index,
        js_api=api,
        width=1040,
        height=700,
        min_size=(840, 560),
        background_color="#15131f",
    )
    debug = os.environ.get("VAULT_DEBUG") == "1"
    webview.start(debug=debug)


if __name__ == "__main__":
    main()
