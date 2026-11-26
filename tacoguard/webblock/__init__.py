"""Phase 4 website blocking. CONTRACT: the "Website blocking" section of tacoguard/phase4.py.

    lists.py      refresh(settings, store, progress=None) -> dict ; load(settings) -> DomainSet ;
                  status(settings) -> dict (what the page shows per list) ; busy(settings) -> bool
    watch.py      WebWatcher(settings, store, checker=None): the guard part "web"
                  (start() / stop() / status() -> the PART dict of tacoguard/guard/__init__.py)
    hosts.py      plan(settings) -> dict ; apply_elevated(settings) -> Outcome ;
                  remove_elevated(settings, cleanup=False) -> Outcome (Outcome: a str with .ok, .code)
    hosts-helper.ps1  the fixed script the admin step runs from "<Program Files>\\TacoGuard" (hosts.py
                  installs it there through the same admin prompt the first time); .NET calls only

Files in settings.webblock_dir:
    current/<source>/domains.txt   one domain per line (newest first), source = "phishing" | "urlhaus"
    current/<source>/domains.bin   the same domains as a sorted array of 8-byte blake2b hashes
    current/<source>/meta.json     {"source", "count", "sha256" (of domains.txt), "bin_sha256",
                                    "fetched", "raw_sha256", "dropped": {...}}
    previous/<source>/             the last good set before that
    staging/                       a refresh run's own downloads and new sets (unique names per run)
    state.json                     per source: last contact with the server, last message
    refresh.lock                   while a refresh runs (any TacoGuard process)
    hosts-list.txt                 the names prepared for the hosts block (the helper checks them)
    hosts-applied.json             written by hosts.py (user level) after it saw the helper's change
"""
