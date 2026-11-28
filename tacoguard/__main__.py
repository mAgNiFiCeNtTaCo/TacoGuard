"""Command line.

    python -m tacoguard serve  [--data DIR] [--port N] [--no-browser]   the local page
    python -m tacoguard scan   PATH [PATH ...] [--data DIR]             scan here, print results
    python -m tacoguard setup  [--data DIR]                             get / refresh signatures
    python -m tacoguard status [--data DIR]                             signature status
    python -m tacoguard install [--shortcut] [--offline]                per-user installed copy
    python -m tacoguard uninstall                                       remove the installed copy
    python -m tacoguard hosts status|remove [--data DIR]                TacoGuard's hosts-file block
    python -m tacoguard selftest [--data DIR]                           check this copy works
    python -m tacoguard version                                         print the version
"""
from __future__ import annotations

import argparse
import json
import sys


def _self_protect(settings) -> None:
    """Phase 4, at page start: harden this process and compare the installed copy's files with
    the list written at install (tacoguard/selfprotect.py). A failure never stops the page."""
    try:
        from . import selfprotect
        selfprotect.maybe_harden(settings)
        if not getattr(settings, "self_protection", True):
            return
        from .store import Store
        problems = selfprotect.check_install(settings)
        if problems:
            st = Store(settings.db_path)
            try:
                selfprotect.report_install_check(settings, st, problems)
            finally:
                st.close()
    except Exception:
        pass


def hosts_command(settings, action: str, *, launcher=None, hosts_path=None, out=print) -> int:
    """`python -m tacoguard hosts status|remove`. remove = one Windows admin prompt through
    TacoGuard's hosts helper (webblock/hosts.py); status only reads. 0 = fine / done."""
    from .webblock import hosts
    if action == "status":
        p = hosts.plan(settings, hosts_path=hosts_path)
        b = p["block"]
        if not b["readable"]:
            out("Windows didn't let TacoGuard read the hosts file.")
            return 1
        out(f"TacoGuard's block is in the hosts file ({b['count']:,} websites)." if b["present"]
            else "The hosts file has no TacoGuard block.")
        out(p["message"])
        return 0
    res = hosts.remove_elevated(settings, launcher=launcher, hosts_path=hosts_path)
    out(str(res))
    return 0 if getattr(res, "ok", False) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tacoguard")
    ap.add_argument("--data", help="data folder (default D:\\TacoGuard or TACOGUARD_DATA)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_serve = sub.add_parser("serve", help="open the local page")
    p_serve.add_argument("--port", type=int)
    p_serve.add_argument("--no-browser", action="store_true")
    p_scan = sub.add_parser("scan", help="scan files, folders or drives and print the results")
    p_scan.add_argument("paths", nargs="+")
    p_scan.add_argument("--json", action="store_true")
    sub.add_parser("setup", help="download / refresh the ClamAV program, signatures and YARA rules")
    sub.add_parser("status", help="show signature status")
    p_inst = sub.add_parser("install", help="install a per-user copy in %%LOCALAPPDATA%%\\Programs\\TacoGuard")
    p_inst.add_argument("--shortcut", action="store_true", help="also add a Start-menu shortcut")
    p_inst.add_argument("--offline", action="store_true",
                        help="copy the needed parts from this Python instead of downloading them with pip")
    sub.add_parser("uninstall", help="remove the installed copy (your data folder is kept)")
    p_hosts = sub.add_parser("hosts", help="TacoGuard's block in Windows' hosts file: status, or remove it")
    p_hosts.add_argument("action", choices=("status", "remove"))
    sub.add_parser("selftest", help="check that this copy of TacoGuard works (nothing is started)")
    sub.add_parser("version", help="print TacoGuard's version")
    args = ap.parse_args(argv)

    from .config import load_settings, secure_root
    from .store import Store

    if args.cmd == "version":
        from . import __version__
        from .selfupdate import running_from_install
        where = "installed copy" if running_from_install() else "project folder"
        print(f"TacoGuard {__version__} ({where})")
        return 0
    if args.cmd == "hosts":
        return hosts_command(load_settings(args.data), args.action)
    if args.cmd in ("install", "uninstall", "selftest"):
        from . import install as inst
        settings = load_settings(args.data)
        if args.cmd == "selftest":
            ok, lines = inst.selftest(settings)
            print("\n".join(lines))
            return 0 if ok else 1
        if args.cmd == "uninstall":
            out = inst.uninstall(settings)
        else:
            from pathlib import Path
            out = inst.install(settings, Path(__file__).resolve().parents[1], shortcut=args.shortcut,
                               deps="copy" if args.offline else "pip", progress=lambda m: print(m, flush=True))
        print(out["message"])
        return 0 if out["ok"] else 1

    settings = load_settings(args.data)
    from .config import DataFolderNotYours
    try:
        secure_root(settings)
    except DataFolderNotYours as e:
        print(str(e), file=sys.stderr, flush=True)
        return 2
    settings.ensure_dirs()

    if args.cmd == "serve":
        from .web.server import serve
        if args.port:
            settings.port = args.port
        from .selfupdate import report_health_when_up
        report_health_when_up(settings)      # installed copy: tells a self-update "started OK"
        _self_protect(settings)
        return serve(settings, open_browser=not args.no_browser) or 0

    if args.cmd == "setup":
        from .setup_fetch import fetch_all
        out = fetch_all(settings, progress=lambda m: print(m, flush=True))
        ok = all(v.get("ok") for v in out.values())
        for name, v in out.items():
            print(f"{name}: {'OK' if v.get('ok') else 'FAILED'} - {v.get('message', '')}")
        return 0 if ok else 1

    if args.cmd == "status":
        from .detect import signature_status
        print(json.dumps(signature_status(settings), indent=2, default=str))
        return 0

    if args.cmd == "scan":
        from .scan.jobs import run_job_inline
        store = Store(settings.db_path)
        job_id = store.create_job(list(args.paths))
        run_job_inline(settings, store, job_id)
        job = store.get_job(job_id)
        found = store.list_results(job_id)
        if args.json:
            print(json.dumps({"job": job, "results": found}, indent=2, default=str))
        else:
            print(job["message"])
            for r in found:
                print(f"[{r['level'].upper() if r['level'] != 'clean' else r['status'].upper()}] {r['path']}")
                print(f"    {r['reason']}")
        c = job["counts"]
        return 2 if (c.get("malware") or c.get("suspicious")) else 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
