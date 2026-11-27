"""Let Windows fetch a missing trusted root certificate, the way Edge or Chrome would.

Windows ships only some root certificates and downloads the rest from Windows Update the first time a
Windows program needs one. Python only sees roots that are already on the PC, so a site whose root
nobody on this PC has used yet fails with "unable to get local issuer certificate" (seen 2026-11-26:
urlhaus-api.abuse.ch, SwissSign RSA TLS Root CA 2022 - 1).

fetch_root(host) reads the site's certificates (a TLS handshake, no request is sent) and asks Windows
to build a chain for them (CertGetCertificateChain). Windows then adds the root only if it is in
Microsoft's trusted root program. Nothing is trusted by TacoGuard itself: the caller retries with
Python's normal, full certificate check. Each host is tried at most once per run.
"""
from __future__ import annotations

import ctypes
import os
import socket
import ssl
import sys
import threading
from ctypes import wintypes

# OpenSSL verify codes meaning "I don't have the issuer" (not "this certificate is bad")
_MISSING_ISSUER = {2, 20}          # unable to get issuer certificate (locally)

_tried: set[str] = set()
_lock = threading.Lock()


def missing_issuer(exc: BaseException | None) -> bool:
    """True when `exc` (or what caused it, e.g. a URLError's reason) is a certificate check that
    failed only because the issuing certificate isn't on this PC."""
    seen = 0
    while exc is not None and seen < 6:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return getattr(exc, "verify_code", None) in _MISSING_ISSUER
        exc = getattr(exc, "reason", None) if isinstance(getattr(exc, "reason", None), BaseException) \
            else (exc.__cause__ or exc.__context__)
        seen += 1
    return False


def _server_chain(host: str, port: int, timeout: float) -> list[bytes]:
    """The certificates the server sends (leaf first), read WITHOUT checking them: they are only
    handed to Windows, which checks them itself."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            getter = getattr(s, "get_unverified_chain", None)     # Python 3.13+
            chain = [c if isinstance(c, bytes) else c.public_bytes(ssl.Encoding.DER) for c in getter()] \
                if getter else []
            return chain or [s.getpeercert(binary_form=True)]


class _CTL_USAGE(ctypes.Structure):
    _fields_ = [("cUsageIdentifier", wintypes.DWORD), ("rgpszUsageIdentifier", ctypes.c_void_p)]


class _CERT_USAGE_MATCH(ctypes.Structure):
    _fields_ = [("dwType", wintypes.DWORD), ("Usage", _CTL_USAGE)]


class _CERT_CHAIN_PARA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("RequestedUsage", _CERT_USAGE_MATCH)]


class _CERT_TRUST_STATUS(ctypes.Structure):
    _fields_ = [("dwErrorStatus", wintypes.DWORD), ("dwInfoStatus", wintypes.DWORD)]


class _CERT_CHAIN_CONTEXT(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("TrustStatus", _CERT_TRUST_STATUS)]


_ENCODING = 0x00010001             # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
_STORE_PROV_MEMORY = 2
_ADD_ALWAYS = 4
# chain problems that are about revocation lookups, not about trust
_REVOCATION_ONLY = 0x00000040 | 0x01000000


def _windows_builds_chain(chain: list[bytes]) -> bool:
    """Ask Windows to build and check a chain for chain[0] (the others help it along). Windows may
    download a missing root from Windows Update while doing this. True when Windows trusts it."""
    c = ctypes.WinDLL("crypt32", use_last_error=True)
    c.CertCreateCertificateContext.restype = ctypes.c_void_p
    c.CertCreateCertificateContext.argtypes = [wintypes.DWORD, ctypes.c_char_p, wintypes.DWORD]
    c.CertOpenStore.restype = ctypes.c_void_p
    c.CertOpenStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    c.CertAddEncodedCertificateToStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_char_p,
                                                   wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    c.CertGetCertificateChain.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.POINTER(_CERT_CHAIN_PARA), wintypes.DWORD, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
    c.CertFreeCertificateChain.argtypes = [ctypes.c_void_p]
    c.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    c.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]

    leaf = c.CertCreateCertificateContext(_ENCODING, chain[0], len(chain[0]))
    if not leaf:
        return False
    store = c.CertOpenStore(_STORE_PROV_MEMORY, 0, None, 0, None)
    chain_ctx = ctypes.c_void_p()
    try:
        for der in chain[1:]:
            if store:
                c.CertAddEncodedCertificateToStore(store, _ENCODING, der, len(der), _ADD_ALWAYS, None)
        para = _CERT_CHAIN_PARA()
        para.cbSize = ctypes.sizeof(para)
        if not c.CertGetCertificateChain(None, leaf, None, store, ctypes.byref(para), 0, None,
                                         ctypes.byref(chain_ctx)) or not chain_ctx.value:
            return False
        status = ctypes.cast(chain_ctx, ctypes.POINTER(_CERT_CHAIN_CONTEXT)).contents.TrustStatus
        return (status.dwErrorStatus & ~_REVOCATION_ONLY) == 0
    finally:
        if chain_ctx.value:
            c.CertFreeCertificateChain(chain_ctx)
        if store:
            c.CertCloseStore(store, 0)
        c.CertFreeCertificateContext(leaf)


def fetch_root(host: str, port: int = 443, timeout: float = 15.0) -> bool:
    """Let Windows add the trusted root `host` needs (see the module notes). True when Windows now
    trusts the site's chain, so a retry with the normal check is worth it. Never raises; Windows
    only; at most once per host per run; never while tests run (they replace it)."""
    if sys.platform != "win32" or os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    host = (host or "").lower()
    with _lock:
        if not host or host in _tried:
            return False
        _tried.add(host)
    try:
        return _windows_builds_chain(_server_chain(host, port, timeout))
    except Exception:
        return False
