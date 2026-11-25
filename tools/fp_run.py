"""False-positive check: scan the program files of folders you trust and count what gets flagged.

    .venv\\Scripts\\python.exe tools\\fp_run.py [FOLDER ...]

Default folders: Program Files, Program Files (x86) and the Steam libraries. Only program-type
files are checked (exe, dll, sys, msi, scripts). Uses the real signatures in the data folder,
runs at the same low priority as a normal scan, and writes results into a throwaway database
(your real results and trusted list are not touched). Report: reports\\fp-<date>.json
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import psutil  # noqa: E402

from tacoguard import allowlist  # noqa: E402
from tacoguard.config import load_settings  # noqa: E402
from tacoguard.detect import load_detectors  # noqa: E402
from tacoguard.model import CLEAN, SCANNED  # noqa: E402
from tacoguard.scan import engine, walker  # noqa: E402
from tacoguard.scan.worker import lower_priority  # noqa: E402
from tacoguard.store import Store  # noqa: E402

PROGRAM_EXT = {".exe", ".dll", ".sys", ".msi", ".scr", ".ocx", ".cpl", ".com", ".drv", ".efi",
               ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar"}


def _steam_roots() -> list[Path]:
    """Steam's own folder (from the registry, else the usual place) plus X:\\Steam on any drive."""
    roots = []
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as k:
            roots.append(Path(winreg.QueryValueEx(k, "SteamPath")[0]))
    except OSError:
        pass
    roots.append(Path(r"C:\Program Files (x86)\Steam"))
    roots += [Path(d) / "Steam" for d in os.listdrives()]
    return roots


def steam_libraries() -> list[str]:
    out = []
    for vdf in (r / "steamapps" / "libraryfolders.vdf" for r in _steam_roots()):
        if vdf.exists():
            for line in vdf.read_text(encoding="utf-8", errors="replace").splitlines():
                if '"path"' in line:
                    p = line.split('"path"', 1)[1].strip().strip('"').replace("\\\\", "\\")
                    common = Path(p) / "steamapps" / "common"
                    if common.is_dir() and str(common) not in out:
                        out.append(str(common))
    return out


def main(argv: list[str]) -> int:
    folders = argv or [r"C:\Program Files", r"C:\Program Files (x86)", *steam_libraries()]
    settings = load_settings()
    applied = lower_priority(settings.scan_priority)
    tmp = tempfile.mkdtemp(prefix="tacoguard-fp-")
    store = Store(Path(tmp) / "fp.db")
    trust = allowlist.TrustChecker(store)
    detectors, notes = engine.open_detectors(load_detectors(settings))
    sig_version = "|".join(d.version() for d in detectors)
    throttle = engine.Throttle(settings.limits.read_rate_mb_s)
    print(f"Priority: {applied}. Detectors: {[d.name for d in detectors]} {notes}")
    print("Folders:", folders, flush=True)

    me = psutil.Process()
    me.cpu_percent()
    t0 = time.time()
    counts = {"files": 0, "bytes": 0, "clean": 0, "flagged": 0, "unreadable": 0, "skipped": 0, "incomplete": 0}
    flagged, unreadable = [], []
    peak_rss, cpu_samples = 0, []
    last = t0
    threads = settings.clamav_thread_count() if hasattr(settings, "clamav_thread_count") else 4
    pool = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="fp-clamav")

    def report(entry, r, _stats):
        nonlocal last, peak_rss
        if r is None:
            return
        counts["files"] += 1
        counts["bytes"] += r.size
        if r.status != SCANNED:
            counts["unreadable" if r.status == "unreadable" else "skipped"] += 1
            if r.status == "unreadable":
                unreadable.append({"path": r.path, "why": r.reason()})
        elif r.level != CLEAN:
            counts["flagged"] += 1
            flagged.append({"path": r.path, "level": r.level, "reason": r.reason(),
                            "findings": [f.to_dict() for f in r.findings]})
            print(f"  FLAGGED [{r.level}] {r.path}\n      {r.reason()[:300]}", flush=True)
        else:
            counts["clean"] += 1
        if r.incomplete:
            counts["incomplete"] += 1
        if time.time() - last > 30:
            last = time.time()
            rss = me.memory_info().rss + sum(c.memory_info().rss for c in me.children(recursive=True))
            peak_rss = max(peak_rss, rss)
            cpu = me.cpu_percent() + sum(c.cpu_percent() for c in me.children(recursive=True))
            cpu_samples.append(cpu / psutil.cpu_count())
            print(f"  {counts['files']:,} files, {counts['bytes'] / 2**30:.1f} GB, "
                  f"{counts['flagged']} flagged, {time.time() - t0:.0f} s", flush=True)

    window = engine._Window(2 * threads, engine.WINDOW_MAX_BYTES, report)
    try:
        for entry in walker.walk(folders, max_file_size=settings.limits.max_file_size):
            if isinstance(entry, walker.WalkNote):
                if entry.kind == "too_big" and Path(entry.display).suffix.lower() in PROGRAM_EXT:
                    counts["skipped"] += 1
                continue
            if Path(entry.display).suffix.lower() not in PROGRAM_EXT:
                continue
            size = entry.st.st_size
            window.make_room(size if size <= settings.limits.in_memory_max else 0)
            pending = engine.check_file(entry, detectors, trust, settings, store, sig_version,
                                        throttle=throttle, pool=pool)
            window.add(entry, pending, {})
        window.drain()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        engine.close_detectors(detectors)
    secs = time.time() - t0
    rate = counts["flagged"] / max(counts["files"], 1)
    report = {"date": time.strftime("%Y-%m-%d %H:%M"), "folders": folders, "sig_version": sig_version,
              "priority": applied, "seconds": round(secs), "counts": counts,
              "false_positive_rate": rate, "peak_ram_mb": round(peak_rss / 2**20),
              "avg_cpu_percent_of_pc": round(sum(cpu_samples) / max(len(cpu_samples), 1), 2),
              "flagged": flagged, "unreadable": unreadable[:200]}
    out = ROOT / "reports" / f"fp-{time.strftime('%Y-%m-%d')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    store.close()
    print(f"\nChecked {counts['files']:,} program files ({counts['bytes'] / 2**30:.1f} GB) in {secs / 60:.1f} min.")
    print(f"Flagged: {counts['flagged']} -> false-positive rate {rate:.4%}. Unreadable: {counts['unreadable']}, "
          f"skipped: {counts['skipped']}, archives not fully checked: {counts['incomplete']}.")
    print(f"Peak RAM (scanner + ClamAV): {report['peak_ram_mb']} MB, average CPU: "
          f"{report['avg_cpu_percent_of_pc']}% of the PC. Report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
