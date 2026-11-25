"""Machine-learning features (tacoguard/ml) and detector (detect/ml.py).

Test material: tests/ml_inputs.py (harmless, built in memory) and real Windows files READ only.
The model in these tests is a tiny LightGBM model trained here on random numbers (it knows
nothing); the real EMBER2024 model is never needed.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path

import numpy as np
import pytest

import ml_inputs
from samples import MARKER
from tacoguard import ml
from tacoguard.detect import load_detectors, signature_status
from tacoguard.detect import ml as mldet
from tacoguard.detect.base import DetectorError, DetectorUnavailable
from tacoguard.ml import _hashing
from tacoguard.model import Confidence, ScanItem

REFERENCE = Path(__file__).resolve().parent / "data" / "ml_reference.json"
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


# ---- features ---------------------------------------------------------------------------------

def test_murmurhash_matches_known_sklearn_values():
    # values from sklearn.utils.murmurhash3_32(s, seed=0, positive=False)
    known = {"": 0, "a": 1009084850, "ab": -1681926305, "abc": -1277324294, "abcd": 1139631978,
             "abcde": -392455434, "\u00e9": 269551495, "\u6f22": 1399629057,
             "kernel32.dll": 814237301}
    for s, h in known.items():
        assert _hashing.murmurhash3_32(s.encode("utf-8")) == h, s


def test_hasher_index_and_sign_rules():
    fh = _hashing.FeatureHasher(50, input_type="string")
    assert fh._index(-2147483648) == (2147483647 - 49) % 50
    assert fh._index(-7) == 7 and fh._index(7) == 7
    row = fh.transform([["a", "a", "ab"]]).toarray()[0]
    # "a" hashes positive (+1 twice), "ab" negative (-1)
    assert row[1009084850 % 50] == 2.0 and row[1681926305 % 50] == -1.0
    nosign = _hashing.FeatureHasher(50, input_type="string", alternate_sign=False)
    assert nosign.transform([["ab"]]).toarray()[0][1681926305 % 50] == 1.0
    pairs = _hashing.FeatureHasher(10, input_type="pair").transform([[("a", 0), ("a", 2.5)]]).toarray()[0]
    assert pairs[1009084850 % 10] == 2.5 and pairs.sum() == 2.5
    assert not _hashing.FeatureHasher(10, input_type="pair").transform([[]]).toarray().any()
    with pytest.raises(ValueError):
        fh.transform(["just a string"])


@pytest.mark.skipif(not NOTEPAD.exists(), reason="notepad.exe not found")
def test_feature_vector_shape_on_real_windows_file():
    v = ml.feature_vector(NOTEPAD.read_bytes())          # read only
    assert v.shape == (ml.FEATURE_DIM,) == (2568,) and v.dtype == np.float32
    assert np.isfinite(v).all()
    assert v[2] == 1                                      # general: is_pe


def test_feature_vector_shape_on_synthetic_inputs():
    for name, data in ml_inputs.synthetic_inputs().items():
        v = ml.feature_vector(data)
        assert v.shape == (2568,), name


def _reference_entries():
    return json.loads(REFERENCE.read_text(encoding="utf-8"))["entries"]


def test_reference_file_is_from_upstream():
    doc = json.loads(REFERENCE.read_text(encoding="utf-8"))
    assert "upstream thrember" in doc["made_with"]
    assert {e["kind"] for e in doc["entries"]} == {"synthetic", "file"}


@pytest.mark.parametrize("entry", _reference_entries(), ids=lambda e: e["name"])
def test_vendored_features_equal_upstream_reference(entry):
    if entry["kind"] == "synthetic":
        data = ml_inputs.synthetic_inputs()[entry["name"]]
    else:
        p = Path(entry["path"])
        if not p.exists():
            pytest.skip(f"{p} not on this PC")
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            pytest.skip(f"{p.name} changed since the reference was made (Windows update)")
    assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    ours = ml.feature_vector(data)
    ref = np.asarray(entry["vector"], dtype=np.float32)
    assert np.array_equal(ours.view(np.uint32), ref.view(np.uint32)), np.nonzero(ours != ref)[0][:10]


def test_known_upstream_quirks_are_kept():
    ext = ml.extractor()
    strings = next(f for f in ext.features if f.name == "strings")
    # issue #7: the email regex is the MAC regex
    assert strings._regexes["email_addr"].pattern == strings._regexes["mac_addr"].pattern
    exports = next(f for f in ext.features if f.name == "exports")
    # issue #8: the export "count" is always the hash width (128)
    assert exports.process_raw_features(["a", "b"])[0] == 128
    section = next(f for f in ext.features if f.name == "section")
    v = section.process_raw_features(section.raw_features(ml_inputs.tiny_pe(), __import__("pefile").PE(data=ml_inputs.tiny_pe())))
    # issue #21: the min entropy / size ratio / vsize ratio are always 0
    assert v[6] == 0 and v[8] == 0 and v[10] == 0


def test_fast_string_counts_equal_upstream_loop():
    strings = next(f for f in ml.extractor().features if f.name == "strings")
    rnd = random.Random(11)
    pieces = ["http://a.b/c", "https://x", "ftp://q", "1.2.3.4", "999.1.1.1", "fe80::1", "::1",
              "00:11:22:33:44:55", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "C:/", "HKCU", "KHLM",
              "/dev/", "/tmp/", "html", "JavaScript", ".click", "onclick", "GET /", "POST /",
              "HTTP/", "User-Agent", "base64", "crypt", "Crypt", "!This program ", "x", "_", "-",
              ":", " ", "a1", "Z", "token", "WINDOW", "Start-process", "Invoke-Command"]
    alphabet = [chr(c) for c in range(0x20, 0x80)]
    for _ in range(300):
        items = []
        for _ in range(rnd.randint(0, 25)):
            s = "".join(rnd.choice(pieces) if rnd.random() < 0.6 else rnd.choice(alphabet)
                        for _ in range(rnd.randint(1, 12)))
            items.append(s if len(s) >= 5 else s + "abcde")
        assert strings._string_counts_fast(items) == strings._string_counts_slow(items), items
    assert strings._string_counts_fast([]) == {}


def test_regexes_cannot_match_a_newline():
    """_string_counts_fast relies on this (strings are joined with '\\n')."""
    from re import _constants as C, _parser
    strings = next(f for f in ml.extractor().features if f.name == "strings")

    def walk(items):
        for op, av in items:
            if op is C.AT:
                assert av in (C.AT_BOUNDARY, C.AT_NON_BOUNDARY), av          # only \b
            elif op is C.ASSERT_NOT or op is C.ASSERT:
                raise AssertionError("look-around")
            elif op is C.IN:
                for kind, val in av:
                    assert kind is not C.NEGATE and kind is not C.CATEGORY, (kind, val)
                    if kind is C.RANGE:
                        assert not val[0] <= 10 <= val[1]
                    if kind is C.LITERAL:
                        assert val != 10
            elif op is C.LITERAL:
                assert av != 10
            elif op in (C.NOT_LITERAL, C.CATEGORY):
                raise AssertionError(op)
            elif op is C.SUBPATTERN:
                walk(av[-1])
            elif op in (C.MAX_REPEAT, C.MIN_REPEAT, C.POSSESSIVE_REPEAT):
                walk(av[2])
            elif op is C.BRANCH:
                for b in av[1]:
                    walk(b)
            # ANY (".") never matches "\n" without DOTALL

    for name, r in strings._regexes.items():
        assert not r.flags & re.DOTALL, name
        walk(_parser.parse(r.pattern, r.flags))
        assert r.search("\n") is None, name


# ---- a tiny model package (random trees, knows nothing) -----------------------------------------

def _make_package(folder: Path, *, medium=0.9, low=0.6) -> dict:
    import lightgbm
    rng = np.random.default_rng(5)
    X = rng.random((120, 2568), dtype=np.float32)
    y = (X[:, 0] > 0.5).astype(int)
    booster = lightgbm.train({"objective": "binary", "verbose": -1, "num_threads": 1,
                              "min_data_in_leaf": 5}, lightgbm.Dataset(X, y), num_boost_round=3)
    folder.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(folder / "model.txt"))
    vector = X[7].tolist()
    score = float(booster.predict(np.asarray([vector], dtype=np.float32), num_threads=1)[0])
    meta = {"version": "2026.11.23", "model_name": "EMBER2024_PE", "source": "https://example.invalid/model",
            "license": "Apache-2.0", "feature_version": 3,
            "sha256": hashlib.sha256((folder / "model.txt").read_bytes()).hexdigest(),
            "thresholds": {"fpr_0.001": medium, "fpr_0.01": low},
            "test_vector": vector, "test_score": score}
    (folder / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return meta


@pytest.fixture
def package(settings):
    meta = _make_package(settings.ml_dir / "current")
    return meta


class FakeBooster:
    def __init__(self, score):
        self.score = score

    def predict(self, x, num_threads=1):
        assert x.shape == (1, 2568)
        return np.array([self.score])


def _opened(settings, score=None):
    det = mldet.MLDetector(settings)
    det.open()
    if score is not None:
        det._booster = FakeBooster(score)
    return det


def test_self_test_passes_on_a_good_package(settings, package):
    mldet.self_test(settings.ml_dir / "current")


def test_self_test_fails_on_wrong_score(settings, package):
    cur = settings.ml_dir / "current"
    meta = json.loads((cur / "meta.json").read_text(encoding="utf-8"))
    meta["test_score"] += 1e-4
    (cur / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(mldet.MLSelfTestFailed, match="built-in test"):
        mldet.self_test(cur)


def test_self_test_fails_on_changed_model_file(settings, package):
    cur = settings.ml_dir / "current"
    with open(cur / "model.txt", "ab") as f:
        f.write(b"\n")
    with pytest.raises(ValueError, match="checksum"):
        mldet.self_test(cur)


@pytest.mark.parametrize("change", [
    lambda m: m.pop("thresholds"),
    lambda m: m.update(thresholds={"fpr_0.001": 0.5, "fpr_0.01": 0.9}),   # medium below low
    lambda m: m.update(feature_version=2),
    lambda m: m.update(test_vector=[0.0] * 10),
])
def test_self_test_fails_on_bad_meta(settings, package, change):
    cur = settings.ml_dir / "current"
    meta = json.loads((cur / "meta.json").read_text(encoding="utf-8"))
    change(meta)
    (cur / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(mldet.MLSelfTestFailed):
        mldet.self_test(cur)


def test_self_test_fails_on_missing_folder(tmp_path):
    with pytest.raises(mldet.MLSelfTestFailed, match="incomplete"):
        mldet.self_test(tmp_path / "nothing")


def test_open_without_model_is_unavailable_in_plain_words(settings):
    det = mldet.MLDetector(settings)
    with pytest.raises(DetectorUnavailable, match="not installed yet"):
        det.open()
    st = det.status()
    assert st["ready"] is False and "Not installed yet" in st["message"] and st["version"] == "ml-none"


def test_status_and_version_with_package(settings, package):
    det = mldet.MLDetector(settings)
    st = det.status()
    assert st["ready"] is True and "EMBER2024_PE" in st["message"] and st["updated"] > 0
    assert det.version() == "ml-2026.11.23-" + package["sha256"][:12] == st["version"]
    det.open()
    assert det.has_signatures()
    det.close()
    det.close()


def test_open_refuses_a_tampered_model(settings, package):
    with open(settings.ml_dir / "current" / "model.txt", "ab") as f:
        f.write(b"\n")
    with pytest.raises(DetectorUnavailable, match="checksum"):
        mldet.MLDetector(settings).open()


@pytest.mark.parametrize("score, confidence", [
    (0.95, Confidence.MEDIUM), (0.9, Confidence.MEDIUM), (1.0, Confidence.MEDIUM),
    (0.89, Confidence.LOW), (0.6, Confidence.LOW), (0.59, None), (0.0, None)])
def test_score_to_confidence(settings, package, score, confidence):
    det = _opened(settings, score)
    found = det.scan(ScanItem(display="x.exe", data=ml_inputs.tiny_pe()))
    if confidence is None:
        assert found == []
        return
    assert len(found) == 1
    f = found[0]
    assert f.confidence == confidence and f.confidence < Confidence.HIGH
    assert f.engine == "ml" and f.rule == "EMBER2024 PE model"
    assert f.source == "machine-learning model (EMBER2024, Apache-2.0)"
    assert f.detail.startswith(f"machine-learning score {score:.2f} (")
    assert "never proof" in f.detail and "malware" in f.detail
    assert f.license == "Apache-2.0"


def test_detail_wording_example(settings, package):
    f = _opened(settings, 0.97).scan(ScanItem(display="x.exe", data=ml_inputs.tiny_pe()))[0]
    assert f.detail == ("machine-learning score 0.97 (it looks like known malware to the model; "
                        "on its own this is never proof)")


def test_non_pe_is_skipped(settings, package):
    det = _opened(settings, 0.99)
    assert det.scan(ScanItem(display="a.txt", data=b"just text " + MARKER)) == []
    assert det.scan(ScanItem(display="empty", data=b"")) == []


def test_size_cap(settings, package, tmp_path):
    settings.ml_max_file_size = 1000
    det = _opened(settings, 0.99)
    big = ml_inputs.tiny_pe(b"\x00" * 2000)
    assert det.scan(ScanItem(display="big.exe", data=big)) == []
    p = tmp_path / "big.exe"
    p.write_bytes(big)
    assert det.scan(ScanItem(display="big.exe", path=str(p), size=len(big))) == []
    assert det.scan(ScanItem(display="big.exe", path=str(p))) == []        # size unknown: still capped
    small = tmp_path / "small.exe"
    small.write_bytes(ml_inputs.tiny_pe()[:900])
    assert len(det.scan(ScanItem(display="small.exe", path=str(small), size=900))) == 1


def test_file_on_disk_is_read(settings, package, tmp_path):
    p = tmp_path / "t.exe"
    p.write_bytes(ml_inputs.tiny_pe())
    det = _opened(settings, 0.95)
    found = det.scan(ScanItem(display="t.exe", path=str(p), size=p.stat().st_size))
    assert [f.confidence for f in found] == [Confidence.MEDIUM]
    txt = tmp_path / "t.txt"
    txt.write_bytes(b"hello")
    assert det.scan(ScanItem(display="t.txt", path=str(txt), size=5)) == []


def test_unreadable_file_is_a_plain_detector_error(settings, package, tmp_path):
    det = _opened(settings, 0.95)
    with pytest.raises(DetectorError, match="could not read this file"):
        det.scan(ScanItem(display="gone.exe", path=str(tmp_path / "gone.exe"), size=10))


def test_extraction_error_gives_no_finding_and_no_note(settings, package):
    det = _opened(settings, 0.99)

    def broken(data):
        raise RuntimeError("regex engine trouble")      # like EMBER2024 issue #10
    det._extract = broken
    assert det.scan(ScanItem(display="odd.exe", data=ml_inputs.tiny_pe())) == []


def test_member_is_kept(settings, package):
    f = _opened(settings, 0.95).scan(ScanItem(display="a.zip > b.exe", data=ml_inputs.tiny_pe(),
                                             member="b.exe", depth=1))[0]
    assert f.member == "b.exe"


# ---- worst-case inputs: too many strings (proof script p_ml_mem.py, 2026-11-23) ---------------

def _string_bomb(size: int) -> bytes:
    """Harmless: 'MZ' and then the word 'files' over and over (one text run every 6 bytes)."""
    return (b"MZ" + b"files\0" * (size // 6 + 1))[:size]


def test_too_many_strings_are_not_scored_and_say_so(settings, package):
    import time
    det = _opened(settings, 0.99)

    def never(data):
        raise AssertionError("the feature code must not run on this file")
    det._extract = never
    data = _string_bomb(8 * 1024**2)                       # ~1.4 million text runs
    t0 = time.perf_counter()
    with pytest.raises(mldet.DetectorNote) as e:
        det.scan(ScanItem(display="bomb.exe", data=data))
    assert time.perf_counter() - t0 < 3
    assert str(e.value) == ("Too many text strings inside to give it a machine-learning score; "
                            "checked with the other methods.")
    assert isinstance(e.value, DetectorError)              # older callers still treat it as a note
    # inside an archive: no finding and no note per member
    assert det.scan(ScanItem(display="a.zip > bomb.exe", data=data, member="bomb.exe", depth=1)) == []


def test_string_caps_count_runs_and_bytes():
    run = b"abcde"                                          # exactly one 5-character run each
    assert mldet.strings_fit(b"MZ" + (run + b"\0") * 10, max_strings=10)
    assert not mldet.strings_fit(b"MZ" + (run + b"\0") * 11, max_strings=10)
    assert not mldet.strings_fit(b"MZ\0" + b"A" * 101, max_bytes=100)  # one long run
    assert mldet.strings_fit(b"MZ\0" + b"A" * 100, max_bytes=100)
    assert mldet.strings_fit(b"MZ" + b"abcd\0" * 1000, max_strings=1)  # 4 characters: not a run
    assert mldet.MAX_STRINGS >= 100_000 and mldet.MAX_STRING_BYTES >= 2 * 1024**2


def test_normal_programs_are_still_scored(settings, package):
    for path in ml_inputs.REFERENCE_FILES:
        data = Path(path).read_bytes()
        assert mldet.strings_fit(data), path
    assert len(_opened(settings, 0.95).scan(ScanItem(display="x.exe", data=ml_inputs.tiny_pe()))) == 1


def test_fast_entropy_is_bit_identical_to_the_counter_loop():
    """TacoGuard change 5 in ml/features.py: same float terms in the same order."""
    import math
    from collections import Counter
    from tacoguard.ml import features as F

    def counter_entropy(data):
        if not data:
            return 0.0
        occ = Counter(bytearray(data))
        e = 0
        for x in occ.values():
            p = float(x) / len(data)
            e -= p * math.log(p, 2)
        return e
    rng = np.random.default_rng(3)
    cases = [b"MZ", b"\x00" * 5000, bytes(range(256)), bytes(range(255, -1, -1)) * 3,
             rng.integers(0, 256, 300_000, dtype=np.uint8).tobytes(),
             rng.integers(0, 8, 2_000_000, dtype=np.uint8).tobytes() + b"\xff",   # a value seen last
             (b"files\0" * 50_000) + bytes(range(200, 256)), ml_inputs.mz_text(), ml_inputs.tiny_pe()]
    for data in cases:
        assert F._entropy_H(data) == counter_entropy(data)               # exactly, not approximately
        a = np.frombuffer(data, dtype=np.uint8)
        assert F._bincount256(a).tolist() == np.bincount(a, minlength=256).tolist()
        assert F._first_seen_order(a, F._bincount256(a)) == list(Counter(bytearray(data)))
    assert F._entropy_H(b"", empty=0) == 0 and F._entropy_H(b"") == 0.0


def test_lowercase_regex_shortcut_equals_upstream_on_mixed_case():
    strings = next(f for f in ml.extractor().features if f.name == "strings")
    assert "html" in strings._lowered and ".click(" in strings._lowered
    assert "url" not in strings._lowered and "get" in strings._lowered
    items = ["HTML page", "hTmL and JAVAscript", "x.CLICK(", "XcLiCk later", "User-AGENT: me",
             "get /index", "GeT /", "Powershell -c", "DOWNLOADS here", "no match at all"]
    assert strings._string_counts_fast(items) == strings._string_counts_slow(items)


def test_scan_before_open_is_an_error(settings, package):
    with pytest.raises(DetectorError):
        mldet.MLDetector(settings).scan(ScanItem(display="x", data=b"MZ"))


def test_real_tiny_model_scores_real_features(settings, package):
    det = _opened(settings)                               # the random tiny model, no fake
    found = det.scan(ScanItem(display="t.exe", data=ml_inputs.tiny_pe()))
    assert all(f.confidence <= Confidence.MEDIUM for f in found)


def test_load_detectors_includes_ml_when_enabled(settings):
    assert "ml" in [d.name for d in load_detectors(settings)]
    names = [d.name for d in load_detectors(settings)]
    assert names.index("yara") < names.index("ml") < names.index("clamav")
    settings.ml_enabled = False
    assert "ml" not in [d.name for d in load_detectors(settings)]
    st = signature_status(settings)
    assert st["ml"]["enabled"] is False and st["ml"]["message"].startswith("Turned off in Settings.")


def test_signature_status_with_ml_package(settings, package):
    st = signature_status(settings)
    assert st["ml"]["ready"] is True
    assert "ml-2026.11.23" in st["sig_version"]


def test_scans_members_flag():
    assert mldet.MLDetector.name == "ml" and mldet.MLDetector.scans_members is True
