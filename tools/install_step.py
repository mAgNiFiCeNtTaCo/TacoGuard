"""TacoGuard's Setup runs this right after it copied its files (installer/TacoGuard.iss):

    <app>\\runtime\\python.exe -I <app>\\setup\\install_step.py --root <app> [--data DIR] [--no-sign-in]

<app>\\setup\\ holds app\\ (TacoGuard's files, as in the project folder) and parts\\ (the pinned
parts, copied from the project's .venv by tools/build_installer.py). This puts both first on
sys.path and runs `python -m tacoguard install --offline` from there: it makes venv\\ from
runtime\\, copies the parts, installs and self-tests this version and switches current.json to it,
exactly as for a copy installed from the project folder. Output goes to <app>\\setup-log.txt
(Setup shows its end when something fails). Exit code 0 = installed.

Standard library only until tacoguard is imported; -I keeps the user's PYTHONPATH and
current folder out.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_NAME = "setup-log.txt"


def tacoguard_args(root, data=None, sign_in=True):
    """The `python -m tacoguard` arguments for Setup's install step."""
    args = ["--data", data] if data else []
    args += ["install", "--offline", "--root", root]
    if not sign_in:
        args.append("--no-sign-in")
    return args


def main(argv=None):
    ap = argparse.ArgumentParser(prog="install_step")
    ap.add_argument("--root", required=True)
    ap.add_argument("--data")
    ap.add_argument("--no-sign-in", action="store_true")
    a = ap.parse_args(argv)
    root = os.path.abspath(a.root)
    log = open(os.path.join(root, LOG_NAME), "w", encoding="utf-8")
    sys.stdout = sys.stderr = log
    try:
        sys.path[0:0] = [os.path.join(HERE, "app"), os.path.join(HERE, "parts")]
        from tacoguard.__main__ import main as tacoguard_main
        code = tacoguard_main(tacoguard_args(root, a.data, sign_in=not a.no_sign_in))
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except Exception as e:                      # shown to the user by Setup
        print(f"TacoGuard's install step stopped: {type(e).__name__}: {e}")
        code = 1
    print(f"(exit code {code})")
    log.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
