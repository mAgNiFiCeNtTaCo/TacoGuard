"""Dev tool: prove TacoGuard's vendored EMBER2024 features (tacoguard/ml) give the SAME vectors as
upstream thrember, and time the feature extraction. Reads files only (never changes them).

Upstream thrember must NEVER be installed into the project's .venv. Use a separate temp venv:
    py -3.14 -m venv <tmp>\\upvenv
    <tmp>\\upvenv\\Scripts\\python.exe -m pip install
        "git+https://github.com/FutureComputing4AI/EMBER2024.git@0ef753e81d98bf209f71b03cd331dfc190b5b54d"
        signify==0.7.1 pefile==2024.8.26 lightgbm==4.7.0 numpy==2.5.5

Steps:
    .venv\\Scripts\\python.exe tools\\ml_compare_upstream.py list <out.txt> [--count 200] [--seed 1]
    <upvenv>\\Scripts\\python.exe tools\\ml_compare_upstream.py upstream <list.txt> <up.npz>
    <upvenv>\\Scripts\\python.exe tools\\ml_compare_upstream.py hasher [--rounds 200000]
    .venv\\Scripts\\python.exe tools\\ml_compare_upstream.py vendored <list.txt> <ours.npz>
    .venv\\Scripts\\python.exe tools\\ml_compare_upstream.py compare <up.npz> <ours.npz>
    <upvenv>\\Scripts\\python.exe tools\\ml_compare_upstream.py reference tests\\data\\ml_reference.json
"""
from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
MAX_SIZE = 64 * 1024**2
LIST_ROOTS = [r"C:\Program Files", r"C:\Program Files (x86)"]
EXTRA = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\cmd.exe",
         r"C:\Windows\System32\kernel32.dll", r"C:\Windows\System32\ntdll.dll",
         r"C:\Windows\explorer.exe", r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"]


def cmd_list(out: str, count: int, seed: int) -> None:
    found = []
    for root in LIST_ROOTS:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not name.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".scr")):
                    continue
                p = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(p)
                    if not 0 < size <= MAX_SIZE:
                        continue
                    with open(p, "rb") as f:
                        if f.read(2) != b"MZ":
                            continue
                except OSError:
                    continue
                found.append(p)
    rnd = random.Random(seed)
    rnd.shuffle(found)
    chosen = [p for p in EXTRA if os.path.exists(p)] + found[:count]
    Path(out).write_text("\n".join(chosen) + "\n", encoding="utf-8")
    print(f"{len(found)} program files found, {len(chosen)} listed in {out}")


def _run(list_file: str, out: str, vector) -> None:
    paths = [p for p in Path(list_file).read_text(encoding="utf-8").splitlines() if p.strip()]
    vectors, kept, times, errors = [], [], [], []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            errors.append(f"{p}: unreadable ({e.__class__.__name__})")
            continue
        t0 = time.perf_counter()
        try:
            v = np.asarray(vector(data), dtype=np.float32)
        except Exception as e:  # report and go on
            errors.append(f"{p}: {e.__class__.__name__}: {e}")
            continue
        times.append(time.perf_counter() - t0)
        vectors.append(v)
        kept.append(p)
    np.savez_compressed(out, paths=np.array(kept), vectors=np.vstack(vectors), times=np.array(times))
    times.sort()
    p95 = times[int(0.95 * (len(times) - 1))] if times else 0.0
    print(f"{len(kept)} files, {len(errors)} errors; extraction time median "
          f"{statistics.median(times) * 1000:.0f} ms, p95 {p95 * 1000:.0f} ms, max {times[-1] * 1000:.0f} ms")
    for e in errors:
        print("  error:", e)


def cmd_upstream(list_file: str, out: str) -> None:
    import thrember  # only in the temp upstream venv
    if "Antivirus" in thrember.__file__:
        sys.exit("refusing: this thrember is not the upstream package")
    ext = thrember.PEFeatureExtractor()
    _run(list_file, out, ext.feature_vector)


def cmd_vendored(list_file: str, out: str) -> None:
    sys.path.insert(0, str(ROOT))
    from tacoguard import ml
    _run(list_file, out, ml.feature_vector)


def cmd_compare(a: str, b: str) -> int:
    A, B = np.load(a), np.load(b)
    pa, pb = list(A["paths"]), list(B["paths"])
    common = [p for p in pa if p in set(pb)]
    ia, ib = {p: i for i, p in enumerate(pa)}, {p: i for i, p in enumerate(pb)}
    diff = 0
    for p in common:
        va, vb = A["vectors"][ia[p]], B["vectors"][ib[p]]
        same = va.shape == vb.shape and np.array_equal(va.view(np.uint32), vb.view(np.uint32))
        if not same:
            diff += 1
            bad = np.nonzero(va != vb)[0][:10]
            print(f"DIFFERENT: {p} at {bad.tolist()}")
    only = (set(pa) ^ set(pb))
    print(f"{len(common)} files compared bit for bit, {diff} different; "
          f"{len(only)} only on one side: {sorted(only)[:5]}")
    return 1 if diff or only else 0


def cmd_reference(out: str) -> None:
    """With UPSTREAM thrember: vectors of tests/ml_inputs.py's inputs -> tests/data/ml_reference.json."""
    import hashlib
    import json
    import thrember
    if "Antivirus" in thrember.__file__:
        sys.exit("refusing: this thrember is not the upstream package")
    sys.path.insert(0, str(ROOT / "tests"))
    import ml_inputs
    ext = thrember.PEFeatureExtractor()
    entries = []
    for name, data in ml_inputs.synthetic_inputs().items():
        entries.append({"name": name, "kind": "synthetic", "sha256": hashlib.sha256(data).hexdigest(),
                        "vector": np.asarray(ext.feature_vector(data), dtype=np.float32).tolist()})
    for path in ml_inputs.REFERENCE_FILES:
        data = Path(path).read_bytes()
        entries.append({"name": Path(path).name, "kind": "file", "path": path,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "vector": np.asarray(ext.feature_vector(data), dtype=np.float32).tolist()})
    doc = {"made_with": "upstream thrember (EMBER2024 commit 0ef753e81d98bf209f71b03cd331dfc190b5b54d)",
           "note": "file entries are only compared while the file still has this sha256",
           "entries": entries}
    Path(out).write_text(json.dumps(doc), encoding="utf-8")
    print(f"{len(entries)} reference vectors written to {out}")


def cmd_hasher(rounds: int) -> int:
    """sklearn's FeatureHasher against tacoguard/ml/_hashing.py on random names and values."""
    import importlib.util
    from sklearn.feature_extraction import FeatureHasher as SkHasher
    from sklearn.utils import murmurhash3_32 as sk_murmur
    spec = importlib.util.spec_from_file_location("tg_hashing", ROOT / "tacoguard" / "ml" / "_hashing.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rnd = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-$@?é漢\u0000 "

    def name() -> str:
        return "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))

    bad = 0
    for _ in range(rounds):
        s = name()
        if mod.murmurhash3_32(s.encode("utf-8")) != sk_murmur(s, seed=0, positive=False):
            bad += 1
    checked = rounds
    for _ in range(rounds // 50):
        n = rnd.choice([10, 32, 50, 128, 256, 1024])
        strings = [name() for _ in range(rnd.randint(0, 60))]
        for alt in (True, False):
            x = SkHasher(n, input_type="string", alternate_sign=alt).transform([strings]).toarray()[0]
            y = mod.FeatureHasher(n, input_type="string", alternate_sign=alt).transform([strings]).toarray()[0]
            bad += not np.array_equal(x, y)
        pairs = [(rnd.choice(strings) if strings and rnd.random() < 0.5 else name(),
                  rnd.choice([0, 1, rnd.randint(0, 2**31), rnd.random() * 8, -rnd.random(), 1e-9 * rnd.random()]))
                 for _ in range(rnd.randint(0, 60))]
        x = SkHasher(n, input_type="pair").transform([pairs]).toarray()[0]
        y = mod.FeatureHasher(n, input_type="pair").transform([pairs]).toarray()[0]
        bad += not np.array_equal(x, y)
        checked += 3
    print(f"hasher: {checked} checks against scikit-learn, {bad} different")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("list"); s.add_argument("out"); s.add_argument("--count", type=int, default=200)
    s.add_argument("--seed", type=int, default=1)
    s = sub.add_parser("upstream"); s.add_argument("list_file"); s.add_argument("out")
    s = sub.add_parser("vendored"); s.add_argument("list_file"); s.add_argument("out")
    s = sub.add_parser("compare"); s.add_argument("a"); s.add_argument("b")
    s = sub.add_parser("hasher"); s.add_argument("--rounds", type=int, default=200000)
    s = sub.add_parser("reference"); s.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "reference":
        cmd_reference(a.out)
        return 0
    if a.cmd == "list":
        cmd_list(a.out, a.count, a.seed)
    elif a.cmd == "upstream":
        cmd_upstream(a.list_file, a.out)
    elif a.cmd == "vendored":
        cmd_vendored(a.list_file, a.out)
    elif a.cmd == "compare":
        return cmd_compare(a.a, a.b)
    elif a.cmd == "hasher":
        return cmd_hasher(a.rounds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
