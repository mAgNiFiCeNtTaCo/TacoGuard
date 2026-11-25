"""Dev tool: build TacoGuard's machine-learning package ml-model-<YYYY.MM.DD>.zip.

The package holds:
    model.txt  the EMBER2024_PE LightGBM model (Hugging Face joyce8/EMBER2024-benchmark-models,
               Apache-2.0), checked against the sha256 Hugging Face publishes for it
    meta.json  version, source, license, feature_version 3, sha256 of model.txt, the two score
               cut-offs, the evaluation numbers, and one test vector + its score (self-test)
    LICENSE    Apache-2.0 text (from the EMBER2024 repository)
    NOTICE     where the model comes from and what TacoGuard computed

The cut-offs come ONLY from EMBER2024's own test set (feature records, no program files):
Win32_test.zip, Win64_test.zip and Dot_Net_test.zip in <cache>\\data. Each record
is turned into a feature vector with tacoguard/ml (identical to upstream thrember), scored, and
the cut-off is the lowest score at which at most 0.1% (or 1%) of the clean records (label 0) are
flagged. Unlabeled records (label null) are skipped. Nothing is tuned on the user's own files.

This is a developer tool: it downloads from huggingface.co and github.com into the dev cache
only (the folder in TACOGUARD_ML_CACHE, else %USERPROFILE%\\.cache\\ember2024; about 10 GB). TacoGuard itself never contacts Hugging Face; it gets the package from its own signed
GitHub releases.

    .venv\\Scripts\\python.exe tools\\build_ml_package.py [--out DIR] [--workers 12]
    .venv\\Scripts\\python.exe tools\\build_ml_package.py --install <zip> --ml-dir <settings.ml_dir>
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CACHE = Path(os.environ.get("TACOGUARD_ML_CACHE") or Path.home() / ".cache" / "ember2024")
MODEL_NAME = "EMBER2024_PE"
MODEL_REPO = "joyce8/EMBER2024-benchmark-models"
MODEL_REVISION = "e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2"   # repo commit on 2026-11-23
MODEL_URL = f"https://huggingface.co/{MODEL_REPO}/resolve/{MODEL_REVISION}/{MODEL_NAME}.model"
MODEL_PAGE = f"https://huggingface.co/{MODEL_REPO}"
# Published by Hugging Face for this file (LFS oid = sha256, also the X-Linked-ETag header).
MODEL_SHA256 = "4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99"
MODEL_SIZE = 3_756_042
EMBER_REPO = "https://github.com/FutureComputing4AI/EMBER2024"
EMBER_COMMIT = "0ef753e81d98bf209f71b03cd331dfc190b5b54d"
LICENSE_URL = f"https://raw.githubusercontent.com/FutureComputing4AI/EMBER2024/{EMBER_COMMIT}/LICENSE"
DATASET = "https://huggingface.co/datasets/joyce8/EMBER2024"
TEST_SETS = {   # file: published sha256 (Hugging Face LFS oid, 2026-11-23)
    "Win32_test.zip": "c05f6562dee3ace4195087be918eb00181e33bc31464c671fb5ba00c9dd5dfdb",
    "Win64_test.zip": "52a5a05c1bfa5bb021bb8b44c2e0afcf8983dfa1c6c0a9d76db393e5c682ce10",
    "Dot_Net_test.zip": "b74c4181dbd77565fce16ba47c8ab0f7c7044ae6d880d859ec2c27365dea6299",
}
FPRS = {"fpr_0.001": 0.001, "fpr_0.01": 0.01}
BATCH = 1000


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "tacoguard-dev-build"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1024 * 1024)
    os.replace(tmp, dest)


def get_model() -> Path:
    path = CACHE / "models" / f"{MODEL_NAME}.model"
    if not path.exists():
        print(f"downloading {MODEL_URL}")
        _download(MODEL_URL, path)
    if path.stat().st_size != MODEL_SIZE or sha256_file(path) != MODEL_SHA256:
        raise SystemExit(f"{path} does not match the sha256 Hugging Face publishes; delete it and retry")
    return path


def get_license() -> bytes:
    path = CACHE / "repo" / "LICENSE"
    if not path.exists():
        path = CACHE / "LICENSE-EMBER2024"
        if not path.exists():
            _download(LICENSE_URL, path)
    text = path.read_bytes()
    if b"Apache License" not in text or b"Version 2.0" not in text:
        raise SystemExit(f"{path} is not the Apache-2.0 license text")
    return text


# ---- scoring the EMBER2024 test set -----------------------------------------------------------

def _low_priority() -> None:
    try:
        import psutil
        psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
    except Exception:
        pass


def _score_member(args) -> dict:
    """Worker: vectorize and score every record of one .jsonl member of a test zip."""
    zip_path, member, model_path = args
    _low_priority()
    import lightgbm
    import numpy as np
    from tacoguard import ml
    ext = ml.extractor()
    booster = lightgbm.Booster(model_file=str(model_path))
    scores, labels, best = [], [], None
    rows, row_labels = [], []

    def flush():
        nonlocal best
        if not rows:
            return
        X = np.vstack(rows).astype(np.float32)
        s = booster.predict(X, num_threads=1)
        scores.extend(s.tolist())
        labels.extend(row_labels)
        i = int(np.argmin(np.abs(s - 0.5)))
        if best is None or abs(s[i] - 0.5) < abs(best[1] - 0.5):
            best = (X[i].tolist(), float(s[i]))
        rows.clear()
        row_labels.clear()

    with zipfile.ZipFile(zip_path) as z, z.open(member) as raw:
        for line in io.TextIOWrapper(raw, encoding="utf-8"):
            if not line.strip():
                continue
            rec = json.loads(line)
            label = rec.get("label")
            rows.append(ext.process_raw_features(rec))
            row_labels.append(-1 if label is None else int(label))
            if len(rows) >= BATCH:
                flush()
        flush()
    return {"zip": Path(zip_path).name, "member": member, "scores": scores, "labels": labels,
            "best": best}


def score_test_sets(model_path: Path, workers: int) -> dict:
    import numpy as np
    cache = CACHE / f"scores_{MODEL_SHA256[:12]}.npz"
    best_file = CACHE / f"scores_{MODEL_SHA256[:12]}_testvector.json"
    if cache.exists() and best_file.exists():
        d = np.load(cache)
        return {"scores": d["scores"], "labels": d["labels"], "kinds": d["kinds"],
                "best": json.loads(best_file.read_text(encoding="utf-8"))}
    jobs = []
    for name, sha in TEST_SETS.items():
        path = CACHE / "data" / name
        if not path.exists():
            raise SystemExit(f"missing {path}: download it from {DATASET} (features only)")
        print(f"checking {name} ...", flush=True)
        if sha256_file(path) != sha:
            raise SystemExit(f"{path} does not match the sha256 Hugging Face publishes")
        with zipfile.ZipFile(path) as z:
            jobs += [(str(path), m, str(model_path)) for m in z.namelist() if m.endswith(".jsonl")]
    t0 = time.time()
    results = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(_score_member, jobs):
            results.append(r)
            print(f"  {r['member']}: {len(r['scores']):,} records ({time.time() - t0:.0f} s)", flush=True)
    scores = np.array([s for r in results for s in r["scores"]], dtype=np.float64)
    labels = np.array([l for r in results for l in r["labels"]], dtype=np.int8)
    kinds = np.array([r["zip"].split("_test")[0] for r in results for _ in r["scores"]])
    # the test vector: the record closest to 0.5 in the first member (a score in the middle
    # changes with almost any change to the model, so the self-test means something)
    vector, score = results[0]["best"]
    best = {"vector": vector, "score": score, "from": f"{results[0]['zip']}/{results[0]['member']}"}
    np.savez_compressed(cache, scores=scores, labels=labels, kinds=kinds)
    best_file.write_text(json.dumps(best), encoding="utf-8")
    return {"scores": scores, "labels": labels, "kinds": kinds, "best": best}


def cutoff(benign, fpr: float) -> float:
    """Lowest score t with (clean records scoring >= t) <= fpr * (clean records)."""
    import numpy as np
    b = np.sort(np.asarray(benign, dtype=np.float64))[::-1]
    k = int(np.floor(fpr * b.size))       # this many clean records may be flagged
    return float(np.nextafter(b[k], np.inf))


def evaluate(scores, labels, kinds) -> tuple[dict, dict]:
    import numpy as np
    benign, malicious = scores[labels == 0], scores[labels == 1]
    thresholds, ev = {}, {"clean_records": int(benign.size), "malware_records": int(malicious.size),
                          "unlabeled_skipped": int((labels == -1).sum()), "by_cutoff": {}}
    for key, fpr in FPRS.items():
        t = cutoff(benign, fpr)
        thresholds[key] = t
        row = {"cutoff": t, "target_fpr": fpr,
               "false_positive_rate": float((benign >= t).mean()),
               "detection_rate": float((malicious >= t).mean()), "by_type": {}}
        for kind in sorted(set(kinds.tolist())):
            sel = kinds == kind
            b, m = scores[sel & (labels == 0)], scores[sel & (labels == 1)]
            row["by_type"][kind] = {"false_positive_rate": float((b >= t).mean()) if b.size else None,
                                    "detection_rate": float((m >= t).mean()) if m.size else None,
                                    "clean": int(b.size), "malware": int(m.size)}
        ev["by_cutoff"][key] = row
    try:
        from sklearn.metrics import roc_auc_score  # optional, only if installed
        sel = labels >= 0
        ev["roc_auc"] = float(roc_auc_score(labels[sel], scores[sel]))
    except ImportError:
        pass
    return thresholds, ev


# ---- the package ------------------------------------------------------------------------------

NOTICE_TEXT = """TacoGuard machine-learning package {version}

model.txt is the EMBER2024 benchmark model "{model}" (LightGBM, binary classifier for Windows
PE files: Win32, Win64 and .NET), unchanged:
    {page}  (revision {revision})
    sha256 {sha}
It is licensed under the Apache License, Version 2.0 (LICENSE in this package).

EMBER2024 is by Robert J. Joyce, Gideon Miller, Phil Roth, Richard Zak, Elliott Zaresky-Williams,
Hyrum Anderson, Edward Raff and James Holt: "EMBER2024 - A Benchmark Dataset for Holistic
Evaluation of Malware Classifiers" (KDD 2025). Code: {repo}

meta.json was written by TacoGuard: the score cut-offs were computed by TacoGuard from the
EMBER2024 test set feature records ({dataset}), at 0.1% and 1% false-positive rate on the clean
records. The test vector is one feature record from that test set.
"""


def build(out_dir: Path, workers: int, version: str) -> Path:
    import lightgbm
    import numpy as np
    from tacoguard import ml
    from tacoguard.detect import ml as mldet

    model_path = get_model()
    license_text = get_license()
    data = score_test_sets(model_path, workers)
    thresholds, ev = evaluate(data["scores"], data["labels"], data["kinds"])
    booster = lightgbm.Booster(model_file=str(model_path))
    vector = [float(v) for v in data["best"]["vector"]]
    test_score = float(booster.predict(np.asarray([vector], dtype=np.float32), num_threads=1)[0])
    meta = {
        "version": version,
        "model_name": MODEL_NAME,
        "source": MODEL_URL,
        "source_page": MODEL_PAGE,
        "license": "Apache-2.0",
        "feature_version": ml.FEATURE_VERSION,
        "feature_dim": ml.FEATURE_DIM,
        "features_from": f"{EMBER_REPO} commit {EMBER_COMMIT} (vendored in tacoguard/ml)",
        "sha256": MODEL_SHA256,
        "num_trees": int(booster.num_trees()),
        "thresholds": thresholds,
        "thresholds_note": ("Scores at which at most 0.1% (fpr_0.001) and 1% (fpr_0.01) of the clean "
                            "programs in EMBER2024's Win32 + Win64 + .NET test sets are flagged."),
        "evaluation": ev,
        "test_vector": vector,
        "test_score": test_score,
        "test_vector_from": data["best"]["from"],
        "created": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    notice = NOTICE_TEXT.format(version=version, model=MODEL_NAME, page=MODEL_PAGE, revision=MODEL_REVISION,
                                sha=MODEL_SHA256, repo=EMBER_REPO, dataset=DATASET)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"ml-model-{version}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        shutil.copyfile(model_path, stage / "model.txt")
        (stage / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
        (stage / "LICENSE").write_bytes(license_text)
        (stage / "NOTICE").write_text(notice, encoding="utf-8")
        mldet.self_test(stage)                       # the same check the updater runs
        tmp_zip = out.with_suffix(".zip.part")
        with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for name in ("model.txt", "meta.json", "LICENSE", "NOTICE"):
                z.write(stage / name, name)
        os.replace(tmp_zip, out)
    _report(meta, out)
    return out


def _report(meta: dict, out: Path) -> None:
    ev = meta["evaluation"]
    print(f"\n{out}  {out.stat().st_size:,} bytes  sha256 {sha256_file(out)}")
    print(f"clean records {ev['clean_records']:,}, malware records {ev['malware_records']:,}, "
          f"unlabeled skipped {ev['unlabeled_skipped']:,}" +
          (f", ROC AUC {ev['roc_auc']:.4f}" if "roc_auc" in ev else ""))
    for key, row in ev["by_cutoff"].items():
        print(f"{key}: cut-off {row['cutoff']:.6f}  false positives {row['false_positive_rate']:.4%}  "
              f"detection {row['detection_rate']:.2%}")
        for kind, r in row["by_type"].items():
            print(f"    {kind}: false positives {r['false_positive_rate']:.4%}, detection {r['detection_rate']:.2%}")
    print(f"test score {meta['test_score']:.8f} ({meta['test_vector_from']})")


def install(zip_path: Path, ml_dir: Path) -> Path:
    """Unpack a package into ml_dir/current after its self-test (dev/test use; the real updater
    does this with verification, previous/ and a journal)."""
    from tacoguard.detect import ml as mldet
    ml_dir = Path(ml_dir)
    ml_dir.mkdir(parents=True, exist_ok=True)
    stage = ml_dir / ".staging-dev"
    if stage.exists():
        shutil.rmtree(stage)
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
        if names != {"model.txt", "meta.json", "LICENSE", "NOTICE"}:
            raise SystemExit(f"unexpected files in {zip_path}: {sorted(names)}")
        z.extractall(stage)
    mldet.self_test(stage)
    current = ml_dir / "current"
    if current.exists():
        shutil.rmtree(current)
    os.replace(stage, current)
    return current


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(CACHE / "packages"))
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--version", default=dt.date.today().strftime("%Y.%m.%d"))
    ap.add_argument("--install", metavar="ZIP")
    ap.add_argument("--ml-dir")
    a = ap.parse_args()
    if a.install:
        if not a.ml_dir:
            ap.error("--install needs --ml-dir")
        print("installed into", install(Path(a.install), Path(a.ml_dir)))
        return 0
    build(Path(a.out), a.workers, a.version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
