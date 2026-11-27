# TacoGuard

A second-opinion malware scanner for Windows 11. It works next to Microsoft Defender, not
instead of it: Defender keeps protecting the PC all the time, and TacoGuard checks files and
folders with other open sources of signatures when you ask it to.

TacoGuard never turns off, weakens or changes Microsoft Defender or any Windows security setting,
and never uploads your files.

## What it does

- **Scans a file, a folder or a whole drive** when you ask. Each file is checked four ways:
  - against lists of known-bad files (by SHA-256 hash),
  - with **ClamAV**, the open-source virus scanner from Cisco Talos, and its signatures,
  - with **YARA rules** from YARA Forge, a curated collection of open rule sets,
  - with a **machine-learning score** for Windows programs (.exe, .dll), from the EMBER2024
    research model. A score on its own can make a file *suspicious*, never *malware*.
- **Looks inside zip, 7z and rar archives**, down to 3 archives deep. It stops on archives built to
  blow up when unpacked ("zip bombs") and tells you which ones it could not fully check.
  Password-protected archives are reported, not guessed at.
- **Says why** for every result: which rule or signature matched, who wrote it, and how sure it is.
  Only strong matches are called *malware*. Weaker ones are called *suspicious*, because game mods,
  trainers, admin tools and packed programs set them off now and then.
- **Signed programs:** if a program carries a valid digital signature from its maker (Windows checks
  it, offline), a weak match on it is set aside with a note and a strong one is shown as
  *suspicious*, never hidden; you can turn this off in Settings.
- **Quarantine:** when you choose to, a file is moved into an encrypted store where it cannot run,
  with its original place, hash and the reason. You can restore it or delete it for good from the
  page. TacoGuard never deletes anything by itself.
- **Trusted list:** trust a file (by its hash) or a whole folder. When you say a result is
  "not a threat", TacoGuard remembers it and won't flag that file again.
- **Learns from you, and only from you:** when you mark 3 different files caught by the same rule
  as "not a threat", that rule counts for less from then on (you can undo it in Settings). The
  machine-learning score and exact known-bad matches are never softened this way. A file
  you confirm as a threat goes on your own known-bad list, so copies of it are caught anywhere.
  TacoGuard never trains on your files and never sends them anywhere.
- **Keeps itself up to date** while it runs: at start and every 4 hours it fetches new ClamAV
  signatures, YARA rules and TacoGuard's own signed packages. Every download is checked before
  use; a broken or tampered update is refused and the last good set stays. Without internet it
  keeps working with what it has.
- **Updates itself only when you say so:** when a new TacoGuard version is out, the page offers it.
  It installs only after you click, checks it again, and goes back to the old version by itself
  if the new one doesn't start.


### Real-time protection

While TacoGuard runs, a small background checker (the "guard") watches as things happen:

- **New and changed files** in Downloads (yours, and a `Downloads` folder at the top of any drive),
  Desktop, Documents and your Startup folder are checked once they finish writing. Half-finished
  downloads are left alone until the browser finishes them.
- **Newly started programs** are checked once (unchanged programs are remembered). A program with a
  strong "malware" result is **paused** (frozen, not closed) and the Protection tab asks what to
  do: **Resume**, **End it** or **Quarantine**. A "suspicious" program is only reported.
- **Ransomware decoys:** a few hidden, ordinary-looking files (a budget, a scan, a receipt) sit in
  Documents, Desktop, Pictures and Downloads. Nobody has a reason to change them; ransomware
  rewrites everything it finds. When one changes, or many files are scrambled at once, TacoGuard
  pauses the programs that were writing heavily at that moment and asks you. A program you know
  (a game, a download, a backup) just needs **Resume**. Decoys never go into OneDrive, and they are
  removed when you switch this off.
- **Start-up entries:** TacoGuard notes what starts with Windows (Run keys, Startup folders,
  scheduled tasks, services and a few rarer places) and tells you about anything new, with the
  program it starts checked. Entries in your own account can be undone (and put back) from the
  page; system-wide ones need administrator rights, so the page says where Windows lets you change
  them.
- **Controlled folder access:** the Protection tab explains Windows Security's own ransomware
  protection and opens it for you. TacoGuard only reads that setting, never changes it.

TacoGuard never quarantines or deletes anything by itself: it pauses, reports and waits for you.
Alerts also show as Windows notifications when notifications are switched on in Windows' settings.


### Bad websites

- **Lists:** TacoGuard downloads a list of active phishing sites (Phishing.Database, free) and, once
  you add your own free abuse.ch key in Settings, URLhaus's list of sites that spread malware.
- **Blocking in every browser:** press **Block in every browser** and Windows asks for administrator
  permission. TacoGuard then writes its own marked section into Windows' `hosts` file, which sends
  each bad site to nowhere (0.0.0.0). The first time, the prompt shows "Windows PowerShell": TacoGuard
  installs a small helper into `C:\Program Files\TacoGuard`, a folder only administrators can change,
  and later updates run that helper (one prompt, at most once a week, or when you click). Lines in
  the hosts file that aren't TacoGuard's stay as they are, and you can take the block out any time
  (Settings, or `python -m tacoguard hosts remove`). Sites you trust go on the "never block" list.
- **Noticing:** where Windows lets a normal account read its list of recently looked-up sites,
  TacoGuard also tells you when your PC looked up a listed site. It never pauses a program for that:
  other sites can share the same address. (Some Windows versions keep that list for administrators;
  then blocking in the hosts file is what protects you.)

### More

- **MalwareBazaar lookup** (with your abuse.ch key): for a file TacoGuard flagged, its fingerprint
  (SHA-256) is looked up on MalwareBazaar, never the file or its name. A file listed there under a
  malware name and without a valid digital signature counts as malware; otherwise the listing is shown
  as a hint, because anyone can upload to MalwareBazaar.
- **Tray icon:** green when all is well, orange when something needs you, grey when protection is
  paused. Right-click: open the page, pause protection for an hour, Game mode, check for updates, quit.
- **Game mode:** turns on by itself during full-screen games and presentations (or from the tray, for
  up to 4 hours). Scans and update checks wait and no notifications pop up; real-time checks keep
  running.
- **Self-protection:** programs without administrator rights can't end or freeze TacoGuard, by accident
  or on purpose (an administrator still can). TacoGuard checks its own installed files at start and
  tells you when its sign-in entry or data folder was changed by another program.

### Your abuse.ch key

URLhaus and MalwareBazaar are run by abuse.ch and need a free personal key: sign in at
https://auth.abuse.ch/ (with GitHub, Google, LinkedIn or X), generate an Auth-Key and paste it into
Settings. It is stored encrypted for your Windows account and only its last 4 characters are ever
shown. abuse.ch's data is free for not-for-profit use; TacoGuard never uses it to train anything.

## Getting started

You need Python 3.14 (Python 3.12 or newer works).

```
cd <the folder you downloaded TacoGuard to>
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m tacoguard install --shortcut
```

`install` puts a copy of TacoGuard in `%LOCALAPPDATA%\Programs\TacoGuard` (no administrator
rights, no service) and, with `--shortcut`, a Start-menu entry. It also makes TacoGuard start
quietly when you sign in (one entry in your account's Run key), so real-time protection is on
whenever you are; switch that off in Settings.
Self-update works only on this installed copy. Start it from the Start menu, or run
`%LOCALAPPDATA%\Programs\TacoGuard\TacoGuard.pyw`.

The page opens in your browser at http://127.0.0.1:8799. Only this PC, and only your Windows
account, can use it. The first time, press **Get signatures**. It downloads the ClamAV program
(about 215 MB), ClamAV's signatures and the YARA rules, checks each download, and keeps them in
`D:\TacoGuard`.

Without the page:

```
python -m tacoguard setup          get / refresh signatures
python -m tacoguard scan D:\Downloads
python -m tacoguard status
python -m tacoguard selftest       check that this copy works
```

## What it uses on your PC

- TacoGuard runs from when you sign in (or when you start it) until you press Quit. While it runs
  it checks for updates at start and every 4 hours (you can change or switch that off in Settings).
- Real-time protection idles at well under 1% of the processor (measured: 0.02%) and, together with
  the page, about 115 MB of memory. Checking new programs leaves memory behind, so for a minute or
  two after a busy moment it can use more; then the guard restarts itself (about two seconds) to
  give it back.
- A scan runs at low priority and reads the disk at a capped speed, so games and other programs
  stay smooth. While ClamAV is loaded (during scans, and for 10 minutes after) it uses 1 to 1.7 GB
  of memory (more when it checks more files at once); it closes by itself after that.
- Speed: ClamAV is the slow part. It checks programs (.exe, .dll) at roughly 3 MB per second with
  4 files at once, so the first scan of a big folder of programs takes a while. Files that haven't
  changed since a clean scan are skipped next time, so later scans are much faster.
- Disk: about 250 MB in `D:\TacoGuard` for the ClamAV program, signatures, rules, the ML model and
  cache, plus whatever you put in quarantine. The folder is locked so only your account and
  administrators can open it.

## Internet use

TacoGuard contacts GitHub (the ClamAV program, the YARA Forge rules and TacoGuard's own signed
releases, each checked before use), `database.clamav.net` (through ClamAV's own updater, which
checks Cisco Talos's digital signatures) and `phish.co.za` (the phishing list, or its GitHub copy).
With your abuse.ch key it also contacts `urlhaus-api.abuse.ch` (the malware-site list) and
`mb-api.abuse.ch` (fingerprints of flagged files only). It does so at start, every 4 hours while it
runs, and when you press **Check for updates**. The Settings page lists every address it can
contact. It never sends your files, their names or anything about you.

Sometimes a site's root certificate isn't on the PC yet: Windows downloads those the first time a
program needs one. When that happens, TacoGuard asks Windows to check the site's certificate, and
Windows fetches the root from Windows Update (`ctldl.windowsupdate.com`), as it does for Edge.
Windows adds only roots that Microsoft trusts, and TacoGuard then tries once more with the full
certificate check.

## How updates are checked

TacoGuard's own packages (the app and the ML model) are listed in a file signed with an Ed25519
key; the matching public key ships inside TacoGuard. An update is refused when the signature
doesn't match, the list has expired, it is older than the one already installed, or a file
doesn't match the size and checksum the list gives. ClamAV signatures are checked by ClamAV's
own signed format; YARA Forge rules by the checksum GitHub publishes for them, then a test load.
New signatures, rules and models go in only after a test load passes, and the previous set is
kept to fall back on.

## Your data folder

`D:\TacoGuard` holds the settings, signatures, the ML model, the results database and the
quarantine. On a PC without a D: drive it is `%LOCALAPPDATA%\TacoGuard` instead. Change it with the `--data` option or the `TACOGUARD_DATA` environment variable.

## Licenses

TacoGuard is under the Apache License 2.0 (`LICENSE`). The programs, signatures, rules, model and
libraries it uses keep their own licenses, listed with their authors in `THIRD_PARTY_LICENSES.md`.

## For developers

Tests: `.venv\Scripts\python.exe -m pip install -e .[test]` then `.venv\Scripts\python.exe -m pytest`.
The only test material is in `tests/samples.py`: the EICAR test string (built in memory, never
written to disk) and harmless files carrying a test marker. Never add real malware samples.
Release tools: `tools/keys.py` (signing keys) and `tools/release.py` (build, verify, publish).
