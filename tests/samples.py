"""Harmless test material. The ONLY test material this project may use:

- the EICAR test string, built in memory at run time and never written to disk
  (Defender would grab the file the moment it lands),
- synthetic files that contain MARKER, matched by the test-only YARA rule and the test-only ClamAV
  signature below. They are plain text bytes; nothing in them can run.

Never download, store or run real malware samples.
"""
from __future__ import annotations

MARKER = b"TACOGUARD-HARMLESS-TEST-SAMPLE-6b1f0c"

TEST_YARA_RULE = r'''
rule TacoGuard_Test_Harmless_Sample
{
    meta:
        description = "Test-only rule: matches TacoGuard's harmless synthetic sample"
        author = "TacoGuard tests"
        score = 80
        license = "Apache-2.0"
    strings:
        $m = "TACOGUARD-HARMLESS-TEST-SAMPLE-6b1f0c"
    condition:
        $m
}

rule TacoGuard_Test_Weak_Sample
{
    meta:
        description = "Test-only low-score rule"
        author = "TacoGuard tests"
        score = 40
        license = "Apache-2.0"
    strings:
        $w = "TACOGUARD-WEAK-TEST-MARKER"
    condition:
        $w
}
'''

WEAK_MARKER = b"TACOGUARD-WEAK-TEST-MARKER"

# ClamAV extended (.ndb) signature: Name:TargetType:Offset:HexSignature
TEST_CLAMAV_NDB = "TacoGuard.Test.HarmlessSample-1:0:*:" + MARKER.hex() + "\n"


def sample_bytes(prefix: bytes = b"harmless test file\r\n", suffix: bytes = b"\r\nend\r\n") -> bytes:
    return prefix + MARKER + suffix


def eicar() -> bytes:
    """The standard EICAR antivirus test string, assembled in memory only."""
    parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"]
    return "".join(parts).encode("ascii")
