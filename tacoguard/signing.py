"""Is a program file digitally signed, and by whom? (Windows' own check, WinVerifyTrust.)

check_signature(long_path) -> SignatureInfo(valid, signer, reason). Only Windows programs and
libraries (files starting with 'MZ') are checked; anything else is "not valid" at once.

Both kinds of signature count:
- embedded: the signature is inside the file (most programs from other companies);
- catalog: Windows keeps the file's hash in a signed catalog (most of Windows' own files).

It never goes to the internet: revocation lists are not fetched (WTD_REVOKE_NONE) and certificate
lookups use only what Windows has cached (WTD_CACHE_ONLY_URL_RETRIEVAL). The scan engine calls it
only for files that already got a finding, so clean files cost nothing.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass

__all__ = ["SignatureInfo", "check_signature"]


@dataclass(frozen=True)
class SignatureInfo:
    valid: bool
    signer: str = ""     # the signer's name from its certificate, e.g. "NVIDIA Corporation"
    reason: str = ""     # plain words: "signed (embedded signature)", "not signed", ...


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


def _guid(d1, d2, d3, *d4) -> GUID:
    return GUID(d1, d2, d3, (ctypes.c_ubyte * 8)(*d4))


WINTRUST_ACTION_GENERIC_VERIFY_V2 = _guid(0x00AAC56B, 0xCD44, 0x11D0,
                                          0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(GUID))]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
                ("cbCalculatedFileHash", wintypes.DWORD), ("pcCatalogContext", ctypes.c_void_p),
                ("hCatAdmin", wintypes.HANDLE)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pInfo", ctypes.c_void_p),          # the union: file or catalog info
                ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR), ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD), ("pSignatureSettings", ctypes.c_void_p)]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
WTD_DISABLE_MD2_MD4 = 0x2000
PROV_FLAGS = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
NO_SIGNATURE = {TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN}
_REASONS = {
    0x80096010: "the signature does not match the file (it was changed after signing)",
    0x800B0101: "the signing certificate has expired",
    0x800B010C: "the signing certificate was revoked",
    0x800B0109: "the signing certificate is not trusted by Windows",
    0x800B010A: "the signing certificate could not be checked",
    0x800B0111: "the signer is explicitly distrusted by Windows",
    0x800B0004: "the signer is not trusted by Windows",
    0x80092026: "Windows' security settings do not allow this signature",
    0x80096019: "the signature uses an algorithm that is not allowed",
    0x80092003: "the file could not be read for the signature check",
}

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wintypes.HANDLE
_k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_k32.ReadFile.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                          ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
_k32.SetFilePointerEx.argtypes = (wintypes.HANDLE, ctypes.c_longlong, ctypes.c_void_p, wintypes.DWORD)
_k32.CloseHandle.argtypes = (wintypes.HANDLE,)
_INVALID_HANDLE = wintypes.HANDLE(-1).value

_wt = ctypes.WinDLL("wintrust", use_last_error=True)
_wt.WinVerifyTrust.restype = ctypes.c_long
_wt.WinVerifyTrust.argtypes = (wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p)
_wt.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
_wt.WTHelperProvDataFromStateData.argtypes = (wintypes.HANDLE,)
_wt.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
_wt.WTHelperGetProvSignerFromChain.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
                                               wintypes.DWORD)
_wt.WTHelperGetProvCertFromChain.restype = ctypes.c_void_p
_wt.WTHelperGetProvCertFromChain.argtypes = (ctypes.c_void_p, wintypes.DWORD)
_wt.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
_wt.CryptCATAdminAcquireContext2.argtypes = (ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(GUID),
                                             wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD)
_wt.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
_wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = (wintypes.HANDLE, wintypes.HANDLE,
                                                     ctypes.POINTER(wintypes.DWORD),
                                                     ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD)
_wt.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
_wt.CryptCATAdminEnumCatalogFromHash.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte),
                                                 wintypes.DWORD, wintypes.DWORD,
                                                 ctypes.POINTER(wintypes.HANDLE))
_wt.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
_wt.CryptCATCatalogInfoFromContext.argtypes = (wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO),
                                               wintypes.DWORD)
_wt.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
_wt.CryptCATAdminReleaseCatalogContext.argtypes = (wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD)
_wt.CryptCATAdminReleaseContext.restype = wintypes.BOOL
_wt.CryptCATAdminReleaseContext.argtypes = (wintypes.HANDLE, wintypes.DWORD)

_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_crypt32.CertGetNameStringW.restype = wintypes.DWORD
_crypt32.CertGetNameStringW.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                        ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD)


def _open(path: str):
    """A read handle that lets other programs keep reading, writing and deleting, or None."""
    h = _k32.CreateFileW(path, 0x80000000, 0x7, None, 3, 0x80, None)   # GENERIC_READ, share all
    return None if h is None or h == _INVALID_HANDLE else h


def _starts_with_mz(h) -> bool:
    buf = (ctypes.c_char * 2)()
    got = wintypes.DWORD(0)
    ok = _k32.ReadFile(h, buf, 2, ctypes.byref(got), None)
    _k32.SetFilePointerEx(h, 0, None, 0)       # back to the start for Windows' own check
    return bool(ok) and got.value == 2 and buf.raw == b"MZ"


def _signer_name(state) -> str:
    """The leaf certificate's display name, read while the verify state is still open."""
    prov = _wt.WTHelperProvDataFromStateData(state)
    if not prov:
        return ""
    sgnr = _wt.WTHelperGetProvSignerFromChain(prov, 0, False, 0)
    if not sgnr:
        return ""
    cert = _wt.WTHelperGetProvCertFromChain(sgnr, 0)      # CRYPT_PROVIDER_CERT*
    if not cert:
        return ""
    # CRYPT_PROVIDER_CERT starts with DWORD cbStruct, then PCCERT_CONTEXT pCert (pointer-aligned)
    pcert = ctypes.c_void_p.from_address(cert + ctypes.sizeof(ctypes.c_void_p)).value
    if not pcert:
        return ""
    buf = ctypes.create_unicode_buffer(512)
    n = _crypt32.CertGetNameStringW(pcert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, len(buf))
    return buf.value.strip() if n > 1 else ""


def _verify(choice: int, info) -> tuple[int, str]:
    """(WinVerifyTrust result as an unsigned 32-bit number, signer name when valid)."""
    data = WINTRUST_DATA(cbStruct=ctypes.sizeof(WINTRUST_DATA), dwUIChoice=WTD_UI_NONE,
                         fdwRevocationChecks=WTD_REVOKE_NONE, dwUnionChoice=choice,
                         pInfo=ctypes.cast(ctypes.pointer(info), ctypes.c_void_p),
                         dwStateAction=WTD_STATEACTION_VERIFY, dwProvFlags=PROV_FLAGS)
    action = GUID.from_buffer_copy(WINTRUST_ACTION_GENERIC_VERIFY_V2)
    try:
        code = _wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF
        signer = _signer_name(data.hWVTStateData) if code == 0 else ""
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        _wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    return code, signer


def _embedded(path: str, h) -> tuple[int, str]:
    info = WINTRUST_FILE_INFO(cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO), pcwszFilePath=path, hFile=h)
    return _verify(WTD_CHOICE_FILE, info)


def _catalog(path: str, h) -> tuple[int, str]:
    """Look the file's hash up in Windows' signed catalogs (SHA-256 ones first, then SHA-1)."""
    best = (TRUST_E_NOSIGNATURE, "")
    for algorithm in ("SHA256", "SHA1"):
        admin = wintypes.HANDLE()
        if not _wt.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, algorithm, None, 0):
            continue
        try:
            size = wintypes.DWORD(0)
            _wt.CryptCATAdminCalcHashFromFileHandle2(admin, h, ctypes.byref(size), None, 0)
            if not size.value:
                continue
            digest = (ctypes.c_ubyte * size.value)()
            if not _wt.CryptCATAdminCalcHashFromFileHandle2(admin, h, ctypes.byref(size), digest, 0):
                continue
            _k32.SetFilePointerEx(h, 0, None, 0)
            cat = _wt.CryptCATAdminEnumCatalogFromHash(admin, digest, size.value, 0, None)
            if not cat:
                continue
            try:
                ci = CATALOG_INFO(cbStruct=ctypes.sizeof(CATALOG_INFO))
                if not _wt.CryptCATCatalogInfoFromContext(cat, ctypes.byref(ci), 0):
                    continue
                tag = bytes(digest).hex().upper()
                info = WINTRUST_CATALOG_INFO(
                    cbStruct=ctypes.sizeof(WINTRUST_CATALOG_INFO), pcwszCatalogFilePath=ci.wszCatalogFile,
                    pcwszMemberTag=tag, pcwszMemberFilePath=path, hMemberFile=h,
                    pbCalculatedFileHash=digest, cbCalculatedFileHash=size.value, hCatAdmin=admin)
                code, signer = _verify(WTD_CHOICE_CATALOG, info)
                if code == 0:
                    return code, signer
                best = (code, "")
            finally:
                _wt.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
        finally:
            _wt.CryptCATAdminReleaseContext(admin, 0)
    return best


def _reason(code: int) -> str:
    if code in NO_SIGNATURE:
        return "not signed"
    return _REASONS.get(code, "the digital signature is not valid")


def check_signature(long_path: str) -> SignatureInfo:
    """Windows' verdict on the file's digital signature. Never raises, never uses the network."""
    try:
        h = _open(long_path)
        if h is None:
            return SignatureInfo(False, "", "the file could not be opened for the signature check")
        try:
            if not _starts_with_mz(h):
                return SignatureInfo(False, "", "not a Windows program, so it carries no signature")
            code, signer = _embedded(long_path, h)
            if code == 0:
                return SignatureInfo(True, signer, "signed (signature inside the file)")
            if code not in NO_SIGNATURE:
                # a broken or untrusted signature inside the file: a catalog must not rescue it
                return SignatureInfo(False, "", _reason(code))
            _k32.SetFilePointerEx(h, 0, None, 0)
            code, signer = _catalog(long_path, h)
            if code == 0:
                return SignatureInfo(True, signer, "signed (Windows catalog signature)")
            return SignatureInfo(False, "", _reason(code))
        finally:
            _k32.CloseHandle(h)
    except Exception:       # a signature check must never break a scan
        return SignatureInfo(False, "", "the signature could not be checked")
