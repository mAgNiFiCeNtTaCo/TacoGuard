"""EMBER2024 feature extraction (feature version 3), vendored from the "thrember" package.

Only the feature extraction is here (features.py, pefile_warnings.txt, _hashing.py); training,
plots and dataset downloads are left out. The model itself is not part of the source code: it
comes as a signed package into settings.ml_dir (see detect/ml.py and updates/__init__.py).

    feature_vector(data: bytes) -> numpy float32 array of FEATURE_DIM numbers
"""
from __future__ import annotations

FEATURE_VERSION = 3
FEATURE_DIM = 2568
UPSTREAM_REPO = "https://github.com/FutureComputing4AI/EMBER2024"
UPSTREAM_COMMIT = "0ef753e81d98bf209f71b03cd331dfc190b5b54d"

_extractor = None


def extractor():
    """One shared PEFeatureExtractor (building it compiles ~76 regular expressions)."""
    global _extractor
    if _extractor is None:
        from .features import PEFeatureExtractor
        _extractor = PEFeatureExtractor()
    return _extractor


def feature_vector(data: bytes):
    return extractor().feature_vector(data)
