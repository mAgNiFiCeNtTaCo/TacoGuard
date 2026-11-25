"""Inputs for the machine-learning feature tests (tests/test_ml.py) and for the reference vectors
in tests/data/ml_reference.json (made by tools/ml_compare_upstream.py reference, with upstream
thrember in a separate temp venv).

Everything here is harmless and built in memory: plain text starting with "MZ", and a
header-only Windows program (PE) whose one section is DATA (not executable) and holds the
harmless test marker from tests/samples.py. There is no code in it; it cannot do anything.
Real Windows files are only READ (C:\\Windows\\System32\\...).
"""
from __future__ import annotations

import struct

from samples import MARKER

REFERENCE_FILES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\shell32.dll",
]


def mz_text() -> bytes:
    """Not a valid PE: "MZ" followed by text that hits many of the string regexes."""
    lines = [
        "MZ this is not a program, just text for TacoGuard's feature tests",
        "visit https://example.com/path?x=1 and http://example.org now",
        "server 192.168.10.20 and fe80:0000:0000:0000:0204:61ff:fe9d:f156 ok",
        "mac 00:1A:2B:3C:4D:5E email-ish 00-1a-2b-3c-4d-5e",
        "wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyT here",
        "C:/Users/test HKCU\\Software KHLM powershell Invoke-Expression Start-process",
        "GET /index.html HTTP/1.1 User-Agent: test Cookie: a=b download connect",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ base64 encode decode crypt",
        "cache certificate clipboard command create debug delete desktop directory disk",
        "environment enum exit file hostname install hidden keyboard memory module mutex",
        "password privilege process remote resource security service shell snapshot system",
        "thread token wallet window html javascript <script .click onclick /dev/ /proc/ /bin/",
        "/usr/ /tmp/ /URI /FlateDecode /EmbeddedFile !This program cannot be run in DOS mode.",
        MARKER.decode("ascii"),
    ]
    return ("\x00\x01".join(lines)).encode("ascii") + bytes(range(256)) * 4


def tiny_pe(overlay: bytes = b"") -> bytes:
    """A header-only 32-bit PE: one read/write DATA section with the test marker, no code."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E1000, 0, 0, 0xE0, 0x0102)
    opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, 0, 0x200, 0, 0x1000, 0x1000, 0x1000)
    opt += struct.pack("<IIIHHHHHHIIIIHHIIIIII", 0x400000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                       0x2000, 0x200, 0, 2, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (16 * 8)
    section = struct.pack("<8sIIIIIIHHI", b".data", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xC0000040)
    head = bytes(dos) + b"PE\x00\x00" + coff + opt + section
    head += b"\x00" * (0x200 - len(head))
    body = (b"harmless test data " + MARKER + b" kernel32.dll CreateFileW").ljust(0x200, b"\x00")
    return head + body + overlay


def synthetic_inputs() -> dict[str, bytes]:
    return {
        "mz_text": mz_text(),
        "tiny_pe": tiny_pe(),
        "tiny_pe_overlay": tiny_pe(b"overlay " * 300 + MARKER),
    }
