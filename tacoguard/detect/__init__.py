"""Detectors: known-bad hash lists, YARA rules (YARA-X), the machine-learning model, ClamAV.

CONTRACT (Helper B fills this in; signatures must stay):

    load_detectors(settings, store=None) -> list[Detector]
        The enabled detectors, NOT opened yet, in this order: hash, yara, ml, clamav.
        Disabled ones (settings.clamav_enabled / yara_enabled / ml_enabled False) are left out.

    signature_status(settings) -> dict
        For the page, cheap, never raises:
        {"hash": {...status...}, "yara": {...}, "ml": {...}, "clamav": {...},
         "sig_version": combined version string}
"""
from __future__ import annotations

from .base import Detector, DetectorError, DetectorNote, DetectorUnavailable  # noqa: F401

ORDER = ("hash", "yara", "ml", "clamav")


def _all_detectors(settings) -> dict:
    from .clamav import ClamAVDetector
    from .hashsets import HashDetector
    from .ml import MLDetector
    from .yara_rules import YaraDetector
    return {"hash": HashDetector(settings), "yara": YaraDetector(settings), "ml": MLDetector(settings),
            "clamav": ClamAVDetector(settings)}


def _enabled(settings) -> dict:
    return {"hash": True, "yara": settings.yara_enabled, "ml": getattr(settings, "ml_enabled", True),
            "clamav": settings.clamav_enabled}


def load_detectors(settings, store=None) -> list:
    found = _all_detectors(settings)
    enabled = _enabled(settings)
    return [found[name] for name in ORDER if enabled[name]]


def signature_status(settings) -> dict:
    out: dict = {}
    try:
        detectors = _all_detectors(settings)
    except Exception as e:  # e.g. yara_x missing from the install
        msg = f"The detectors could not be loaded: {e}"
        blank = {"ready": False, "message": msg, "version": "none", "updated": 0.0, "count": 0}
        out = {name: dict(blank) for name in ORDER}
        out["sig_version"] = "none"
        return out
    enabled = _enabled(settings)
    for name in ORDER:
        st = detectors[name].status()
        st["enabled"] = bool(enabled[name])
        if not enabled[name]:
            st["message"] = "Turned off in Settings. " + st["message"]
        out[name] = st
    out["sig_version"] = "|".join(out[n]["version"] for n in ORDER if enabled[n])
    return out
