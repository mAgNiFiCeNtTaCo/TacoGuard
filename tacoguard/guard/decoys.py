"""Decoy files for the ransomware guard (guard/ransom.py): small, valid, harmless documents.

Every decoy is made here, in code: a Word document and an Excel sheet (zip + hand-written XML),
a one-page PDF and a small grayscale JPEG (a baseline JPEG written byte by byte). Their text and
numbers are random filler, so no two PCs share a decoy hash. Names look ordinary and start with
"!" so they sort first (ransomware often walks a folder alphabetically). Neither the names nor
the contents say what they are for: malware skips files that look like traps.

Files are created HIDDEN (not SYSTEM), with an older modified date, and never over an existing
file (exclusive create). Overwriting one of our own decoys uses r+b, because Windows refuses a
plain "wb" open of a hidden file.
"""
from __future__ import annotations

import ctypes
import io
import os
import random
import time
import zipfile
from ctypes import wintypes
from xml.sax.saxutils import escape

from .. import winpath

KINDS = ("docx", "xlsx", "pdf", "jpg")
EXT_KIND = {".docx": "docx", ".xlsx": "xlsx", ".pdf": "pdf", ".jpg": "jpg", ".jpeg": "jpg"}

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def _year() -> int:
    return time.localtime().tm_year


def _names(kind: str) -> list[str]:
    y = _year()
    return {
        "xlsx": [f"!Budget {y}.xlsx", "!Expenses.xlsx", f"!Accounts {y - 1}.xlsx", "!Invoices.xlsx",
                 "!Household budget.xlsx", "!Inventory.xlsx", f"!Savings {y}.xlsx"],
        "docx": ["!Notes.docx", "!Letter.docx", "!CV.docx", "!Meeting notes.docx", "!Contract.docx",
                 "!Report.docx", "!To do.docx"],
        "pdf": ["!Tax return.pdf", "!Invoice 0001.pdf", "!Bank statement.pdf", "!Insurance.pdf",
                "!Receipt.pdf", f"!Payslip {y}.pdf", "!Lease agreement.pdf"],
        "jpg": ["!Scan_0001.jpg", "!IMG_0001.jpg", "!Photo 001.jpg", "!DSC_0001.jpg", "!Scan_0002.jpg",
                "!IMG_0002.jpg", "!Passport scan.jpg"],
    }[kind]


def kind_of(name: str) -> str:
    return EXT_KIND.get(os.path.splitext(name)[1].casefold(), "pdf")


def plan(folder_label: str, count: int, rng: random.Random, taken: set[str]) -> list[tuple[str, str]]:
    """(file name, kind) for `count` decoys in one folder. `taken` holds names (casefolded) already
    used in any folder; chosen names are added to it so folders get different names."""
    label = (folder_label or "").casefold()
    kinds = list(KINDS)
    rng.shuffle(kinds)
    if "picture" in label or "photo" in label:
        kinds.remove("jpg")
        kinds.insert(0, "jpg")
    elif "download" in label:
        kinds.remove("pdf")
        kinds.insert(0, "pdf")
    out: list[tuple[str, str]] = []
    for i in range(count):
        kind = kinds[i % len(kinds)]
        pool = [n for n in _names(kind) if n.casefold() not in taken]
        if not pool:
            pool = [n for k in KINDS for n in _names(k) if n.casefold() not in taken]
            if not pool:
                break
        name = rng.choice(pool)
        taken.add(name.casefold())
        out.append((name, kind_of(name)))
    return out


# ---------------------------------------------------------------------------------------------
# filler text
# ---------------------------------------------------------------------------------------------
_SUBJECTS = ["the bank", "the landlord", "the dentist", "the insurance", "the car service", "school",
             "the plumber", "the energy company", "the gym", "the accountant", "mum", "the garage"]
_TASKS = ["Call {s} about the new card", "Pay {s} before the end of the month", "Ask {s} for a receipt",
          "Send the signed form to {s}", "Check the last letter from {s}", "Book a time with {s}",
          "Cancel the old plan with {s}", "Email {s} the new address", "Find the reference number for {s}"]
_ITEMS = ["Rent", "Groceries", "Electricity", "Water", "Internet", "Phone", "Car insurance", "Fuel",
          "Gym", "Streaming", "Clothes", "Gifts", "Holiday", "Repairs", "Savings", "Childcare", "Pets"]


def _lines(rng: random.Random, n: int) -> list[str]:
    out = []
    for _ in range(n):
        line = rng.choice(_TASKS).format(s=rng.choice(_SUBJECTS))
        if rng.random() < 0.4:
            line += f" (ref {rng.randint(1000, 99999)})"
        out.append(line)
    return out


# ---------------------------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------------------------
_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"


def _zip(parts: list[tuple[str, str]]) -> bytes:
    buf = io.BytesIO()
    stamp = time.localtime(time.time() - random.randint(30, 400) * 86400)[:6]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, text.encode("utf-8"))
    return buf.getvalue()


def make_docx(rng: random.Random) -> bytes:
    paras = [rng.choice(["Notes", "To do", "Things to sort out", "Reminders"])]
    paras += _lines(rng, rng.randint(6, 14))
    body = "".join(f"<w:p><w:r><w:t xml:space=\"preserve\">{escape(p)}</w:t></w:r></w:p>" for p in paras)
    return _zip([
        ("[Content_Types].xml", _XML +
         '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
         '<Default Extension="xml" ContentType="application/xml"/>'
         '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
         'officedocument.wordprocessingml.document.main+xml"/></Types>'),
        ("_rels/.rels", _XML + f'<Relationships xmlns="{_PKG_REL}">'
         f'<Relationship Id="rId1" Type="{_REL}/officeDocument" Target="word/document.xml"/></Relationships>'),
        ("word/document.xml", _XML +
         '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
         + body + '<w:sectPr/></w:body></w:document>'),
    ])


def make_xlsx(rng: random.Random) -> bytes:
    def cell_s(ref: str, text: str) -> str:
        return f'<c r="{ref}" t="inlineStr"><is><t>{escape(text)}</t></is></c>'

    items = rng.sample(_ITEMS, rng.randint(7, 12))
    rows = [f'<row r="1">{cell_s("A1", "Item")}{cell_s("B1", "Month")}{cell_s("C1", "Amount")}</row>']
    for i, item in enumerate(items, start=2):
        amount = round(rng.uniform(8, 1400), 2)
        rows.append(f'<row r="{i}">{cell_s(f"A{i}", item)}{cell_s(f"B{i}", rng.choice(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]))}'
                    f'<c r="C{i}"><v>{amount}</v></c></row>')
    sheet = "".join(rows)
    main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    return _zip([
        ("[Content_Types].xml", _XML +
         '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
         '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
         '<Default Extension="xml" ContentType="application/xml"/>'
         '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-'
         'officedocument.spreadsheetml.sheet.main+xml"/>'
         '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-'
         'officedocument.spreadsheetml.worksheet+xml"/></Types>'),
        ("_rels/.rels", _XML + f'<Relationships xmlns="{_PKG_REL}">'
         f'<Relationship Id="rId1" Type="{_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>'),
        ("xl/workbook.xml", _XML + f'<workbook xmlns="{main}" xmlns:r="{_REL}"><sheets>'
         '<sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        ("xl/_rels/workbook.xml.rels", _XML + f'<Relationships xmlns="{_PKG_REL}">'
         f'<Relationship Id="rId1" Type="{_REL}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'),
        ("xl/worksheets/sheet1.xml", _XML + f'<worksheet xmlns="{main}"><sheetData>{sheet}</sheetData></worksheet>'),
    ])


def _pdf_text(s: str) -> str:
    return s.replace("\\", "").replace("(", "").replace(")", "")


def make_pdf(rng: random.Random) -> bytes:
    lines = [rng.choice(["Statement", "Summary", "Receipt", "Account overview"])]
    lines += _lines(rng, rng.randint(5, 12))
    lines.append(f"Total: {rng.randint(20, 4000)}.{rng.randint(0, 99):02d}")
    ops = ["BT", "/F1 12 Tf", "16 TL", "72 720 Td"]
    for i, line in enumerate(lines):
        ops.append(f"({_pdf_text(line)}) Tj" if i == 0 else f"T* ({_pdf_text(line)}) Tj")
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1", "replace")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# ---- a baseline grayscale JPEG, one flat 8x8 block at a time (DC only) --------------------------
_QUANT = bytes([16, 11, 12, 14, 12, 10, 16, 14, 13, 14, 18, 17, 16, 19, 24, 40, 26, 24, 22, 22, 24, 49,
                35, 37, 29, 40, 58, 51, 61, 60, 57, 51, 56, 55, 64, 72, 92, 78, 64, 68, 87, 69, 55, 56,
                80, 109, 81, 87, 95, 98, 103, 104, 103, 62, 77, 113, 121, 112, 100, 120, 92, 101, 103, 99])
_DC_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]     # the standard luminance DC table
_DC_VALS = list(range(12))
_AC_BITS = [0, 2] + [0] * 14                                   # just EOB (0x00) and one spare symbol
_AC_VALS = [0x00, 0x01]


def _huff_codes(bits: list[int], vals: list[int]) -> dict[int, tuple[int, int]]:
    codes, code, k = {}, 0, 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            codes[vals[k]] = (code, length)
            code += 1
            k += 1
        code <<= 1
    return codes


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def make_jpeg(rng: random.Random) -> bytes:
    w, h = rng.choice([(160, 120), (192, 144), (240, 160), (200, 152)])
    bw, bh = (w + 7) // 8, (h + 7) // 8
    base, gx, gy = rng.randint(60, 190), rng.uniform(-3, 3), rng.uniform(-3, 3)
    dc_codes, ac_codes = _huff_codes(_DC_BITS, _DC_VALS), _huff_codes(_AC_BITS, _AC_VALS)

    acc, nbits, data = 0, 0, bytearray()

    def put(value: int, length: int) -> None:
        nonlocal acc, nbits
        acc = (acc << length) | (value & ((1 << length) - 1))
        nbits += length
        while nbits >= 8:
            nbits -= 8
            byte = (acc >> nbits) & 0xFF
            data.append(byte)
            if byte == 0xFF:
                data.append(0x00)          # byte stuffing
        acc &= (1 << nbits) - 1 if nbits else 0

    prev = 0
    for by in range(bh):
        for bx in range(bw):
            v = base + gx * bx + gy * by + rng.uniform(-10, 10)
            v = max(0, min(255, int(v)))
            dc = round((v - 128) / 2)          # 8 * mean / quant[0] (16)
            diff, prev = dc - prev, dc
            size = abs(diff).bit_length()
            code, length = dc_codes[size]
            put(code, length)
            if size:
                put(diff if diff >= 0 else diff + (1 << size) - 1, size)
            code, length = ac_codes[0x00]      # end of block: every other coefficient is zero
            put(code, length)
    if nbits:
        put((1 << (8 - nbits)) - 1, 8 - nbits)  # pad the last byte with 1 bits

    out = bytearray(b"\xff\xd8")
    out += _segment(0xE0, b"JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00")
    out += _segment(0xDB, b"\x00" + _QUANT)
    out += _segment(0xC0, b"\x08" + h.to_bytes(2, "big") + w.to_bytes(2, "big") + b"\x01\x01\x11\x00")
    out += _segment(0xC4, b"\x00" + bytes(_DC_BITS) + bytes(_DC_VALS))
    out += _segment(0xC4, b"\x10" + bytes(_AC_BITS) + bytes(_AC_VALS))
    out += _segment(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    out += data
    out += b"\xff\xd9"
    return bytes(out)


MAKERS = {"docx": make_docx, "xlsx": make_xlsx, "pdf": make_pdf, "jpg": make_jpeg}


def make(kind: str, rng: random.Random | None = None) -> bytes:
    return MAKERS[kind](rng or random.SystemRandom())


# ---------------------------------------------------------------------------------------------
# files on disk
# ---------------------------------------------------------------------------------------------
def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    k.GetFileAttributesW.restype = wintypes.DWORD
    k.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    k.SetFileAttributesW.restype = wintypes.BOOL
    return k


def attributes(path: str) -> int | None:
    a = _k32().GetFileAttributesW(winpath.to_long(path))
    return None if a == INVALID_FILE_ATTRIBUTES else int(a)


def set_hidden(path: str) -> bool:
    """Adds HIDDEN to the file's attributes (never SYSTEM)."""
    k = _k32()
    a = k.GetFileAttributesW(winpath.to_long(path))
    if a == INVALID_FILE_ATTRIBUTES:
        return False
    a = (a | FILE_ATTRIBUTE_HIDDEN) & ~0x80          # drop FILE_ATTRIBUTE_NORMAL if present
    return bool(k.SetFileAttributesW(winpath.to_long(path), a))


def _age(path: str, rng: random.Random) -> None:
    t = time.time() - rng.randint(20, 500) * 86400 - rng.randint(0, 86399)
    try:
        os.utime(winpath.to_long(path), (t, t))
    except OSError:
        pass


def write_new(path: str, data: bytes, rng: random.Random | None = None) -> None:
    """Creates a NEW hidden file (FileExistsError when anything already has that name)."""
    rng = rng or random.SystemRandom()
    with open(winpath.to_long(path), "xb") as f:
        f.write(data)
    _age(path, rng)
    set_hidden(path)


def overwrite(path: str, data: bytes, rng: random.Random | None = None) -> None:
    """Puts fresh decoy content into an existing decoy path (r+b: works on hidden files)."""
    rng = rng or random.SystemRandom()
    if winpath.is_reparse(os.lstat(winpath.to_long(path))):
        # a link put in its place: writing would change the file it points to. Not ours any more.
        raise FileExistsError(17, "not a plain file")
    with open(winpath.to_long(path), "r+b") as f:
        f.write(data)
        f.truncate()
    _age(path, rng)
    set_hidden(path)
