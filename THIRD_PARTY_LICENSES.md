# Third-party software, rules and data

TacoGuard's own code is under the Apache License 2.0 (see `LICENSE`). It does not include any of
the programs, signatures or rules below in its source code (the one exception is the EMBER2024
feature code in `tacoguard/ml/`, Apache-2.0, kept with its NOTICE); they are downloaded to your PC when you
press **Get / refresh signatures**, straight from their publishers, and checked before use.
Licenses were checked on each project's own pages on 2026-11-23.

## Used in Phase 1

| What | Used for | License | Where it comes from |
|---|---|---|---|
| ClamAV 1.5.5 (Cisco Talos) | Virus scanner engine (runs as a separate program, not built into TacoGuard) | GPL-2.0 with OpenSSL exception; bundled parts listed in its own `COPYING` folder | https://github.com/Cisco-Talos/clamav |
| UnRAR (inside ClamAV, `libclamunrar`) | ClamAV reading RAR archives | UnRAR license: free to use and pass on; may not be used to re-create RAR compression | https://www.rarlab.com/license.htm |
| ClamAV signature databases (main, daily, bytecode) | Virus signatures | Published by Cisco Talos for use with ClamAV; downloaded only with ClamAV's own updater (freshclam), never copied or re-hosted by TacoGuard. No separate written license was found | https://www.clamav.net |
| YARA Forge rule packages (core) | Curated YARA rules | Each rule keeps the license of the project that wrote it, named in the rule itself. Release 20261122: 3,014 rules kept from Signature Base, SEKOIA, DitekSHen, CAPE (GPL-3.0), Volexity, FireEye Red Team, GCTI, ESET, Trellix, WithSecure, Elceef, Cod3nym, craiu, Deutsche Telekom, Dr4k0nia and Synacktiv (Detection Rule License 1.1, BSD, MIT, Apache-2.0, GPL-3.0). 2,064 rules dropped because YARA Forge records no license file for their source. YARA Forge itself is GPL-3.0 | https://github.com/YARAHQ/yara-forge |
| YARA-X (VirusTotal) | Engine that runs the YARA rules | BSD-3-Clause | https://github.com/VirusTotal/yara-x |
| cryptography | Quarantine encryption (AES-256-GCM) | Apache-2.0 or BSD-3-Clause | https://github.com/pyca/cryptography |
| py7zr | Reading 7z archives | LGPL-2.1-or-later (used unchanged, as a library) | https://github.com/miurahr/py7zr |
| rarfile | Reading RAR archive listings | ISC | https://github.com/markokr/rarfile |
| libarchive / bsdtar (part of Windows) | Unpacking RAR archives | BSD-2-Clause | https://github.com/libarchive/libarchive |
| psutil | Low scan priority, process checks | BSD-3-Clause | https://github.com/giampaolo/psutil |
| Python 3.14 | Runs TacoGuard | PSF License | https://www.python.org |
| pytest (tests only) | Tests | MIT | https://github.com/pytest-dev/pytest |

### Attribution for YARA rules

Every detection made by a YARA rule names the rule, its author and its license on the result and on
the Settings page. The Detection Rule License 1.1 (used by Florian Roth's Signature Base and others)
asks for exactly that: the rule's author and source stay visible.

## Used in Phase 2: machine-learning score

| What | Used for | License | Where it comes from |
|---|---|---|---|
| EMBER2024 benchmark model `EMBER2024_PE` (Joyce et al., KDD 2025) | Machine-learning score for Windows programs (PE files). Comes as TacoGuard's signed `ml-model-<date>.zip` (model unchanged, sha256 `4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99`, with the license and a NOTICE inside) | Apache-2.0 | https://huggingface.co/joyce8/EMBER2024-benchmark-models |
| EMBER2024 test set feature records (Win32, Win64, .NET) | Only on the developer's PC, to compute the score cut-offs (0.1% and 1% false positives on clean programs). Feature numbers only, no program files; never shipped | Apache-2.0 | https://huggingface.co/datasets/joyce8/EMBER2024 |
| thrember feature code (EMBER2024), vendored in `tacoguard/ml/` | Turns a program into the 2,568 numbers the model reads. Copied from commit `0ef753e8` with the changes listed at the top of `tacoguard/ml/features.py` (none changes a number); see `tacoguard/ml/NOTICE` | Apache-2.0 | https://github.com/FutureComputing4AI/EMBER2024 |
| LightGBM 4.7 (Microsoft) | Runs the model | MIT | https://github.com/microsoft/LightGBM |
| NumPy | Numbers for the features and the model | BSD-3-Clause (bundled parts: 0BSD, MIT, Zlib, CC0-1.0) | https://github.com/numpy/numpy |
| SciPy | Needed by LightGBM; also adds up the hashed features exactly as upstream does | BSD-3-Clause (bundled parts listed in its LICENSE) | https://github.com/scipy/scipy |
| narwhals | Needed by LightGBM 4.7 | MIT | https://github.com/narwhals-dev/narwhals |
| pefile 2024.8.26 | Reads Windows program headers for the features | MIT | https://github.com/erocarrera/pefile |
| signify 0.7.1 (pinned: 0.8 changed how it parses signatures, EMBER2024 issues #4/#13/#14) | Reads the digital-signature block for the features (parsing only; TacoGuard's own trust check is Windows' WinVerifyTrust) | MIT | https://github.com/ralphje/signify |
| asn1crypto, oscrypto, certvalidator | Needed by signify | MIT | https://github.com/wbond/asn1crypto, https://github.com/wbond/oscrypto, https://github.com/wbond/certvalidator |
| mscerts | Needed by signify (Microsoft's list of trusted root certificates) | MPL-2.0 (used unchanged, as a library) | https://github.com/ralphje/mscerts |
| typing_extensions | Needed by signify | PSF-2.0 | https://github.com/python/typing_extensions |
| MurmurHash3 (Austin Appleby), as used by scikit-learn's FeatureHasher | Re-written in `tacoguard/ml/_hashing.py` (scikit-learn itself is not used) | Public domain (MurmurHash3); scikit-learn BSD-3-Clause | https://github.com/aappleby/smhasher |

## Used in Phase 4: MalwareBazaar hash lookup

| What | Used for | License / terms | Where it comes from |
|---|---|---|---|
| MalwareBazaar (abuse.ch, run with Spamhaus) | Looks up the SHA-256 fingerprint of a file TacoGuard already flagged, and of a file you press **Look up** for, to see whether it is known malware. Only works after you paste your own free abuse.ch key in Settings | abuse.ch Terms of Use: free for not-for-profit use by signed-in users, within abuse.ch's usage limits; commercial users may need a paid Spamhaus subscription. The data may not be used to train or improve AI models, and TacoGuard does not use it that way. TacoGuard sends only the file's SHA-256 hash and your key (never the file, its name or its contents), asks at most 30 times an hour and keeps answers for 7 days (1 day for "not known"). Checked 2026-11-26 | https://bazaar.abuse.ch, terms: https://abuse.ch/terms-of-use/ |

## Used in Phase 4: website blocking

| What | Used for | License / terms | Where it comes from |
|---|---|---|---|
| Phishing.Database (Mitchell Krog and contributors) | The list of active phishing websites ("phishing-domains-ACTIVE"): TacoGuard warns when this PC visits one, and blocks them in Windows' hosts file if you turn that on. Downloaded from phish.co.za at most every 30 minutes (with the regular update check), checked, then kept in the data folder | MIT | https://github.com/Phishing-Database/Phishing.Database, list: https://phish.co.za/latest/phishing-domains-ACTIVE.txt |
| URLhaus (abuse.ch, run with Spamhaus) | The list of websites that spread malware: TacoGuard warns (and pauses a program that isn't a browser) when one is contacted, and blocks them in the hosts file if you turn that on. Only works after you paste your own free abuse.ch key in Settings | abuse.ch Terms of Use: free for not-for-profit use with your own key, within abuse.ch's limits (TacoGuard downloads at most every 30 minutes; abuse.ch asks for no more than every 5). The data may not be used to train or improve AI models, and TacoGuard does not use it that way. It is not re-hosted: each user's own copy of TacoGuard downloads it with that user's key. Checked 2026-11-26 | https://urlhaus.abuse.ch, terms: https://abuse.ch/terms-of-use/ |

## Looked at and not used

| What | Why not |
|---|---|
| OpenPhish community feed | Its terms allow personal use only and forbid building products on it |
| NIST NSRL known-good hash set | 18.8 GB, far over TacoGuard's 1 GB disk budget |
| Elastic's YARA rules | Elastic License 2.0 does not fit an Apache-2.0 tool (YARA Forge leaves them out too) |
| YARA Forge rules whose source has no license file in YARA Forge's record (R3c0nst, DelivrTo, Malpedia, Arkbird SOLG, SecuInfra, RussianPanda, CadoSecurity, Check Point, BlackBerry, Cluster25, Microsoft, NCSC, EmbeeResearch, Avast TI, SBousseaden, HarfangLab, ArtifactDrop) | No license file means no clear permission to use. Some of these rules name a license inside their own text (BlackBerry and CadoSecurity say Apache-2.0); they stay out until that is confirmed at the source |
