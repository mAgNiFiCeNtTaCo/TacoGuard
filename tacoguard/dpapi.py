"""Windows DPAPI (CryptProtectData / CryptUnprotectData) for the current user, via ctypes.

Data protected here can only be unprotected by the same Windows account on this PC.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes

CRYPTPROTECT_UI_FORBIDDEN = 0x1
# Fixed extra secret: another program running as the same user would also need this value.
_ENTROPY = b"TacoGuard quarantine key v1"


class DpapiError(OSError):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_P = ctypes.POINTER(_Blob)
_crypt32.CryptProtectData.argtypes = [_P, wintypes.LPCWSTR, _P, ctypes.c_void_p, ctypes.c_void_p,
                                      wintypes.DWORD, _P]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = [_P, ctypes.c_void_p, _P, ctypes.c_void_p, ctypes.c_void_p,
                                        wintypes.DWORD, _P]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p


def _take(out: _Blob) -> bytes:
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    src, _keep = _blob(bytes(data))
    ent, _keep2 = _blob(_ENTROPY)
    out = _Blob()
    if not _crypt32.CryptProtectData(ctypes.byref(src), "TacoGuard", ctypes.byref(ent), None, None,
                                     CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise DpapiError(ctypes.get_last_error(), "Windows could not protect the data.")
    return _take(out)


def unprotect(data: bytes) -> bytes:
    src, _keep = _blob(bytes(data))
    ent, _keep2 = _blob(_ENTROPY)
    out = _Blob()
    if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent), None, None,
                                       CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise DpapiError(ctypes.get_last_error(), "Windows could not unlock the data "
                         "(it belongs to another user account or is damaged).")
    return _take(out)
