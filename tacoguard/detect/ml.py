"""Machine-learning detector: the EMBER2024 LightGBM model scores Windows programs (PE files).

Folder layout (settings.ml_dir):
    current/   model.txt (LightGBM text model), meta.json, LICENSE, NOTICE  (one ML package)
    previous/  the package before the last update (the updater keeps it for roll-back)

meta.json: {"version": "2026.11.23", "model_name": "EMBER2024_PE", "source": URL,
            "license": "Apache-2.0", "feature_version": 3, "sha256": <of model.txt>,
            "thresholds": {"fpr_0.001": float, "fpr_0.01": float}, "test_vector": [2568 floats],
            "test_score": float, ...}
The thresholds are the scores at which 0.1% and 1% of the clean programs in EMBER2024's own test
set would be flagged (tools/build_ml_package.py). ML alone is never HIGH:
    score >= fpr_0.001 -> MEDIUM, score >= fpr_0.01 -> LOW, below -> no finding.

Only items that start with "MZ" and are at most settings.ml_max_file_size bytes are scored.
A file the feature code cannot parse gets no finding and no note: a broken or odd program is
not a sign of anything, and the other checks still run on it.

The feature code makes Python objects for every printable text run (5+ characters) and runs 76
regexes over all of them, so a file made of millions of short strings took 70 s and 2.7 GB.
Before scoring, strings_fit() counts the runs at native speed and stops at MAX_STRINGS runs or
MAX_STRING_BYTES bytes of them; a file over either cap gets no score and no finding, and (only
for a file on disk, not one inside an archive) the note TOO_MANY_STRINGS_NOTE (a DetectorNote:
the file is not "incompletely checked"). Measured 2026-11-23 on 200 programs from
C:\\Program Files: see config.Settings.ml_max_file_size for the numbers.

self_test(folder) is what the updater runs on a new package before switching to it.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
from pathlib import Path

from ..model import Confidence, Finding, ScanItem, plain_error
from .base import DetectorError, DetectorNote, DetectorUnavailable

MODEL_FILE = "model.txt"
META_FILE = "meta.json"
FEATURE_DIM = 2568
FEATURE_VERSION = 3
SELF_TEST_TOLERANCE = 1e-6
RULE = "EMBER2024 PE model"
SOURCE = "machine-learning model (EMBER2024, Apache-2.0)"
AUTHOR = "EMBER2024 authors (Joyce et al., 2025)"
DETAIL_MEDIUM = "it looks like known malware to the model; on its own this is never proof"
DETAIL_LOW = "it looks a little like known malware to the model; on its own this is never proof"

MAX_STRINGS = 200_000
MAX_STRING_BYTES = 4 * 1024**2
TOO_MANY_STRINGS_NOTE = ("Too many text strings inside to give it a machine-learning score; checked "
                         "with the other methods.")
_STRING_RUN = re.compile(rb"[\x20-\x7f]{5,}")      # the same runs as ml/features.py StringExtractor

log = logging.getLogger(__name__)


def strings_fit(data: bytes, max_strings: int = MAX_STRINGS, max_bytes: int = MAX_STRING_BYTES) -> bool:
    """False when `data` holds more than max_strings printable runs or more than max_bytes bytes
    in them. Stops counting at the cap, keeps no strings, so it is quick and small for any input."""
    n = total = 0
    for m in _STRING_RUN.finditer(data):
        n += 1
        total += m.end() - m.start()
        if n > max_strings or total > max_bytes:
            return False
    return True


class MLSelfTestFailed(ValueError):
    """A model package failed its check. The message is plain English."""


def read_meta(folder: Path) -> dict:
    try:
        meta = json.loads((Path(folder) / META_FILE).read_bytes().decode("utf-8"))
        return meta if isinstance(meta, dict) else {}
    except (OSError, ValueError):
        return {}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _thresholds(meta: dict) -> tuple[float, float]:
    """(medium cut-off, low cut-off). Raises MLSelfTestFailed when they are missing or odd."""
    t = meta.get("thresholds")
    try:
        medium, low = float(t["fpr_0.001"]), float(t["fpr_0.01"])
    except (TypeError, KeyError, ValueError):
        raise MLSelfTestFailed("The machine-learning package has no valid score cut-offs.") from None
    if not (math.isfinite(medium) and math.isfinite(low) and 0.0 < low <= medium <= 1.0):
        raise MLSelfTestFailed("The machine-learning package has score cut-offs that make no sense.")
    return medium, low


def _load_booster(folder: Path, meta: dict):
    """Checks the model file against meta.json and loads it. Raises MLSelfTestFailed."""
    folder = Path(folder)
    model = folder / MODEL_FILE
    if not model.is_file() or not meta:
        raise MLSelfTestFailed("The machine-learning package is incomplete (model or meta.json missing).")
    if int(meta.get("feature_version", 0) or 0) != FEATURE_VERSION:
        raise MLSelfTestFailed("The machine-learning package was made for a different feature version.")
    expected = str(meta.get("sha256", "")).lower()
    if not expected or _sha256(model) != expected:
        raise MLSelfTestFailed("The machine-learning model file does not match its checksum.")
    try:
        import lightgbm
    except ImportError as e:
        raise MLSelfTestFailed("The LightGBM library is missing from this TacoGuard install.") from e
    try:
        booster = lightgbm.Booster(model_file=str(model))
    except Exception as e:  # LightGBM raises its own error type for a broken file
        raise MLSelfTestFailed("The machine-learning model file could not be loaded.") from e
    if booster.num_feature() != FEATURE_DIM:
        raise MLSelfTestFailed("The machine-learning model expects a different number of features.")
    return booster


def _predict(booster, vector) -> float:
    import numpy as np
    x = np.asarray(vector, dtype=np.float32).reshape(1, -1)
    return float(booster.predict(x, num_threads=1)[0])


def self_test(folder) -> None:
    """Load the package in `folder` and check it gives meta["test_score"] for meta["test_vector"]
    (within 1e-6). Raises MLSelfTestFailed (a ValueError) with plain words when anything is off."""
    folder = Path(folder)
    meta = read_meta(folder)
    booster = _load_booster(folder, meta)
    _thresholds(meta)
    vector, expected = meta.get("test_vector"), meta.get("test_score")
    if not isinstance(vector, list) or len(vector) != FEATURE_DIM or not isinstance(expected, (int, float)):
        raise MLSelfTestFailed("The machine-learning package has no valid built-in test.")
    try:
        got = _predict(booster, vector)
    except Exception as e:
        raise MLSelfTestFailed("The machine-learning model could not score its built-in test.") from e
    if not abs(got - float(expected)) <= SELF_TEST_TOLERANCE:
        raise MLSelfTestFailed(f"The machine-learning model gave {got:.6f} on its built-in test "
                               f"instead of {float(expected):.6f}.")


class MLDetector:
    name = "ml"
    scans_members = True

    def __init__(self, settings):
        self.ml_dir = Path(settings.ml_dir)
        self.max_size = int(getattr(settings, "ml_max_file_size", 16 * 1024**2))
        self._booster = None
        self._medium = self._low = 1.0
        self._meta: dict = {}
        self._extract = None
        self._lock = threading.Lock()

    @property
    def current(self) -> Path:
        return self.ml_dir / "current"

    def version(self) -> str:
        meta = read_meta(self.current)
        if not meta:
            return "ml-none"
        return f"ml-{meta.get('version', 'unknown')}-{str(meta.get('sha256', ''))[:12]}"

    def status(self) -> dict:
        try:
            meta = read_meta(self.current)
            ready = bool(meta) and (self.current / MODEL_FILE).is_file()
            if ready:
                msg = (f"Machine-learning model {meta.get('model_name', 'EMBER2024')} "
                       f"(version {meta.get('version', 'unknown')}), scores Windows programs up to "
                       f"{self.max_size // 1024**2} MB.")
                updated = (self.current / META_FILE).stat().st_mtime
            else:
                msg = "Not installed yet: it comes with TacoGuard's next update check."
                updated = 0.0
            return {"ready": ready, "message": msg, "version": self.version(), "updated": updated,
                    "count": 0}
        except Exception as e:  # status must never raise
            return {"ready": False, "message": f"Could not read the machine-learning model: {plain_error(e)}",
                    "version": "ml-none", "updated": 0.0, "count": 0}

    def open(self) -> None:
        meta = read_meta(self.current)
        if not meta or not (self.current / MODEL_FILE).is_file():
            raise DetectorUnavailable("The machine-learning model is not installed yet; it comes with "
                                      "the next update check")
        try:
            from .. import ml as features
            features.extractor()                 # imports pefile and signify, builds the regexes
            self._medium, self._low = _thresholds(meta)
            self._booster = _load_booster(self.current, meta)
        except ImportError as e:
            raise DetectorUnavailable("A library the machine-learning check needs is missing from this "
                                      "TacoGuard install") from e
        except MLSelfTestFailed as e:
            raise DetectorUnavailable(f"{str(e).rstrip('.')}. The next update check downloads it again") from e
        self._extract = features.feature_vector
        self._meta = meta

    def has_signatures(self) -> bool:
        return self._booster is not None

    def _data(self, item: ScanItem) -> bytes | None:
        if item.data is not None:
            data = item.data
            return data if data[:2] == b"MZ" and len(data) <= self.max_size else None
        if not item.path:
            return None
        if item.size and item.size > self.max_size:
            return None
        try:
            with open(item.path, "rb") as f:
                if f.read(2) != b"MZ":
                    return None
                f.seek(0)
                data = f.read(self.max_size + 1)
        except OSError as e:
            raise DetectorError(f"The machine-learning check could not read this file ({plain_error(e)}).") from e
        return data if len(data) <= self.max_size else None

    def scan(self, item: ScanItem) -> list[Finding]:
        if self._booster is None or self._extract is None:
            raise DetectorError("The machine-learning model is not loaded.")
        data = self._data(item)
        if data is None:
            return []
        if not strings_fit(data):
            if item.member:                       # inside an archive: no note per member
                return []
            raise DetectorNote(TOO_MANY_STRINGS_NOTE)
        try:
            vector = self._extract(data)
        except MemoryError:
            raise
        except Exception:   # odd or broken program (also the regex RuntimeError of issue #10)
            log.debug("ML features failed for %s", item.display, exc_info=True)
            return []
        try:
            with self._lock:
                score = _predict(self._booster, vector)
        except MemoryError:
            raise
        except Exception as e:
            raise DetectorError("The machine-learning model could not score this file.") from e
        return self.findings_for(score, item.member)

    def findings_for(self, score: float, member: str = "") -> list[Finding]:
        """The finding for one score (none below the low cut-off)."""
        if not math.isfinite(score) or score < self._low:
            return []
        if score >= self._medium:
            confidence, detail = Confidence.MEDIUM, DETAIL_MEDIUM
        else:
            confidence, detail = Confidence.LOW, DETAIL_LOW
        return [Finding("ml", RULE, confidence, SOURCE,
                        detail=f"machine-learning score {score:.2f} ({detail})", member=member,
                        author=AUTHOR, license="Apache-2.0",
                        reference=str(self._meta.get("source", "")))]

    def close(self) -> None:
        self._booster = None
        self._extract = None
