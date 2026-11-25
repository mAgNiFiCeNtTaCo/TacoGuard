from __future__ import annotations

import os
import zipfile

import pytest

import samples
from tacoguard.detect.base import DetectorError, DetectorUnavailable
from tacoguard.detect import yara_rules as Y
from tacoguard.model import Confidence, ScanItem

MARKER = samples.MARKER.decode()

# A small package in YARA Forge's own layout (package header, imports, one comment block per
# source repository with its LICENSE text, rules at column 0 with meta first).
FORGE_PACKAGE = r'''/*
 * YARA-Forge YARA Rule Package
 * https://github.com/YARAHQ/yara-forge
 *
 * Rule Package Information
 * Name: core
 * Number of Rules: 6
 */

import "pe"


/*
 * YARA Rule Set
 * Repository Name: Good Source
 * Repository: https://github.com/example/good-rules
 * Retrieval Date: 2026-11-22
 * Number of Rules: 4
 *
 *
 * LICENSE
 *
 * # Detection Rule License (DRL) 1.1
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this rule set
 */
rule GOOD_Strong_Marker : FILE
{
	meta:
		description = "Finds the harmless test marker"
		author = "Test Author"
		reference = "https://example.com/article"
		source_url = "https://github.com/example/good-rules/blob/abc/test.yar#L1-L10"
		license_url = "https://github.com/example/good-rules/blob/abc/LICENSE"
		score = 85

	strings:
		$a = "TACOGUARD-HARMLESS-TEST-SAMPLE-6b1f0c"
		$tricky = "rule fake { condition: true }"
		$re = /x{2,3}\}/

	condition:
		$a or ( $tricky and $re )
}
rule GOOD_No_Score
{
	meta:
		description = "Weak marker without a score"
		author = "Test Author"
		license_url = "https://github.com/example/good-rules/blob/abc/LICENSE"

	strings:
		$w = "TACOGUARD-WEAK-TEST-MARKER"

	condition:
		$w
}
private rule GOOD_Helper_NC
{
	meta:
		license = "CC BY-NC 4.0"

	strings:
		$h = "never-used-helper-string"

	condition:
		$h
}
rule GOOD_Uses_NC_Helper
{
	meta:
		score = 90

	condition:
		GOOD_Helper_NC
}

/*
 * YARA Rule Set
 * Repository Name: Unlicensed Source
 * Repository: https://github.com/example/no-license
 * Number of Rules: 1
 *
 *
 * LICENSE
 *
 * NO LICENSE SET
 */
rule NOLIC_Marker
{
	meta:
		license_url = "N/A"
		score = 100

	strings:
		$a = "TACOGUARD-HARMLESS-TEST-SAMPLE-6b1f0c"

	condition:
		$a
}

/*
 * YARA Rule Set
 * Repository Name: Elastic Copy
 * Repository: https://github.com/elastic/protections-artifacts
 * Number of Rules: 1
 *
 *
 * LICENSE
 *
 * Elastic License 2.0
 */
rule ELASTIC_Marker
{
	meta:
		score = 100

	strings:
		$a = "TACOGUARD-HARMLESS-TEST-SAMPLE-6b1f0c"

	condition:
		$a
}
'''

SLOW_RULE = '''
rule TacoGuard_Test_Slow
{
    condition:
        for all i in (0..filesize) : (for all j in (0..filesize) : (uint8(i) != 1 or uint8(j) != 2))
}
'''


def _package_zip(tmp_path, text=FORGE_PACKAGE):
    path = tmp_path / "yara-forge-rules-core.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("packages/core/", "")
        z.writestr("packages/core/yara-rules-core.yar", text)
    return path


def _custom(settings, text=samples.TEST_YARA_RULE, name="test.yar"):
    folder = settings.yara_dir / "custom"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


# ---- layout parsing and license filter -----------------------------------------------------

def test_parse_keeps_rules_whole_even_with_braces_in_strings():
    imports, sources = Y.parse_forge_package(FORGE_PACKAGE)
    assert imports == ['import "pe"']
    assert [s.name for s in sources] == ["Good Source", "Unlicensed Source", "Elastic Copy"]
    good = sources[0]
    assert [r.name for r in good.rules] == ["GOOD_Strong_Marker", "GOOD_No_Score",
                                            "GOOD_Helper_NC", "GOOD_Uses_NC_Helper"]
    assert good.declared == len(good.rules)
    assert '$tricky = "rule fake { condition: true }"' in good.rules[0].text
    assert good.rules[0].meta["source_url"].startswith("https://github.com/example/good-rules")


def test_license_filter_counts_and_reasons():
    imports, sources = Y.parse_forge_package(FORGE_PACKAGE)
    entries = {e["name"]: e for e in Y.apply_policy(imports, sources, Y.load_policy())}
    good = entries["Good Source"]
    assert good["license"] == "DRL 1.1"
    assert (good["kept"], good["dropped"]) == (2, 2)     # NC helper and the rule that uses it
    assert "GOOD_Helper_NC" not in good["text"] and "GOOD_Uses_NC_Helper" not in good["text"]
    assert entries["Unlicensed Source"]["kept"] == 0
    assert entries["Unlicensed Source"]["reason"] == "no license file"
    assert entries["Elastic Copy"]["kept"] == 0


def test_license_short_takes_the_first_license_named():
    policy = Y.load_policy()
    cape_like = ("Cuckoo Sandbox is licensed under the following GNU General Public License version 3.\n"
                 "... a bundled part uses the Apache License ...")
    assert Y.license_short(cape_like, policy) == "GPL-3.0"
    assert Y.license_short("MIT License\nCopyright (c) 2022", policy) == "MIT"
    assert Y.license_short("All rights reserved.", policy) == ""
    gpl_words = "GNU GENERAL PUBLIC LICENSE Version 3 ... only occasionally and noncommercially ..."
    assert Y.apply_policy([], [Y.ForgeSource("G", "https://x/y", gpl_words, 0, [])],
                          policy)[0]["reason"] == ""


def test_installed_package_scans_with_forge_source_names(settings, tmp_path):
    meta = Y.install_package(_package_zip(tmp_path), settings.yara_dir / "current",
                             release="20261122", sha256="ab" * 32, published="2026-11-22T06:26:18Z")
    assert (meta["kept"], meta["dropped"]) == (2, 4)
    assert not list((settings.yara_dir / "current").glob("*.yar"))   # text stays inside the zip
    det = Y.YaraDetector(settings)
    st = det.status()
    assert st["ready"] and st["count"] == 2
    assert st["message"] == "YARA Forge rules from 2026-11-22 (release 20261122, 2 rules)."
    det.open()
    found = det.scan(ScanItem(display="x", data=samples.sample_bytes()))
    assert [f.rule for f in found] == ["GOOD_Strong_Marker"]          # the unlicensed copies never load
    f = found[0]
    assert f.confidence == Confidence.HIGH
    assert f.source == "YARA Forge: Good Source (DRL 1.1)"
    assert f.author == "Test Author" and f.license == "DRL 1.1"
    assert f.reference.startswith("https://github.com/example/good-rules/blob/")
    assert f.detail == "Finds the harmless test marker"
    weak = det.scan(ScanItem(display="w", data=samples.WEAK_MARKER))
    assert [(w.rule, w.confidence) for w in weak] == [("GOOD_No_Score", Confidence.MEDIUM)]
    assert list((settings.yara_dir / "current").glob("compiled-*.bin"))
    det.close()


def test_compiled_cache_is_reused(settings, tmp_path):
    folder = settings.yara_dir / "current"
    Y.install_package(_package_zip(tmp_path), folder, release="r1", sha256="cd" * 32)
    Y.compile_folder(folder)
    cache = next(folder.glob("compiled-*.bin"))
    stamp = cache.stat().st_mtime_ns
    rules, _ = Y.compile_folder(folder)
    assert cache.stat().st_mtime_ns == stamp
    assert rules.scan(samples.sample_bytes()).matching_rules


# ---- your own rules, scores, files on disk, timeouts ---------------------------------------

def test_not_downloaded_is_unavailable(settings):
    det = Y.YaraDetector(settings)
    assert det.status()["ready"] is False
    with pytest.raises(DetectorUnavailable):
        det.open()


@pytest.mark.parametrize("score,expected", [(100, Confidence.HIGH), (80, Confidence.HIGH),
                                            (79, Confidence.MEDIUM), (60, Confidence.MEDIUM),
                                            (59, Confidence.LOW), (None, Confidence.MEDIUM)])
def test_score_to_confidence(score, expected):
    assert Y.score_confidence(score) == expected


def test_custom_rules_high_and_low_in_memory(settings):
    _custom(settings)
    det = Y.YaraDetector(settings)
    det.open()
    high = det.scan(ScanItem(display="x", data=samples.sample_bytes(), member="a\\b.txt"))
    assert [(f.rule, f.confidence, f.source) for f in high] == [
        ("TacoGuard_Test_Harmless_Sample", Confidence.HIGH, "your own rules")]
    assert high[0].member == "a\\b.txt"
    low = det.scan(ScanItem(display="x", data=b"..." + samples.WEAK_MARKER))
    assert [(f.rule, f.confidence) for f in low] == [("TacoGuard_Test_Weak_Sample", Confidence.LOW)]
    assert det.scan(ScanItem(display="x", data=b"nothing here")) == []


def test_file_on_disk_with_a_path_over_260_characters(settings, tmp_path):
    _custom(settings)
    det = Y.YaraDetector(settings)
    det.open()
    deep = "\\\\?\\" + str(tmp_path)
    for i in range(6):
        deep += f"\\level{i}_" + "x" * 45
    os.makedirs(deep)
    path = deep + "\\sample.txt"
    assert len(path) > 260
    with open(path, "wb") as f:
        f.write(samples.sample_bytes())
    found = det.scan(ScanItem(display="deep", path=path))
    assert [f.rule for f in found] == ["TacoGuard_Test_Harmless_Sample"]
    with pytest.raises(DetectorError, match="could not read"):
        det.scan(ScanItem(display="gone", path=deep + "\\missing.bin"))


def test_broken_custom_file_is_skipped_with_a_note(settings):
    _custom(settings)
    _custom(settings, "rule broken { condition: nope( }", name="broken.yar")
    det = Y.YaraDetector(settings)
    det.open()
    assert any("broken.yar" in p for p in det.problems)
    assert det.scan(ScanItem(display="x", data=samples.sample_bytes()))


def test_timeout_becomes_a_plain_detector_error(settings):
    _custom(settings, SLOW_RULE)
    det = Y.YaraDetector(settings, timeout_s=1)
    det.open()
    with pytest.raises(DetectorError, match="took longer than 1 seconds"):
        det.scan(ScanItem(display="big", data=b"\0" * 300_000))
