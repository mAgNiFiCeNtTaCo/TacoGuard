"""Where TacoGuard's own signed packages come from.

A source holds the files of ONE release: targets.json, the files it lists, and root.json /
root-<N>.json when the release keys changed. Two kinds:

    GitHubReleaseSource(repo)   the LATEST GitHub release of config.RELEASE_REPO (api.github.com,
                                downloads from github.com -> release-assets.githubusercontent.com;
                                every host must be in config.ENDPOINTS, HTTPS only, timeouts,
                                resumable .part downloads)
    LocalFolderSource(path)     a folder with the same files (tests, first install, release check)

Both offer:
    refresh() -> None                       read the release listing (once per check)
    fetch_bytes(name, max_size) -> bytes | None     a small file (metadata); None when absent
    download(name, dest, entry, progress) -> Path   a listed file into dest; the length in the
                                            signed entry caps the download; NOT yet verified
Nothing from a source is trusted until signed.verify_* accepted it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .. import setup_fetch
from .signed import META_MAX, TARGET_NAME

NOT_PUBLISHED = "TacoGuard's own update channel isn't published yet."


class SourceError(Exception):
    """Plain-English message. kind: "offline", "not_published", "missing", "http", "too_big", ""."""

    def __init__(self, message: str, kind: str = ""):
        super().__init__(message)
        self.kind = kind


def _safe_name(name: str) -> str:
    if not TARGET_NAME.fullmatch(name or "") or ".." in name:
        raise SourceError(f"TacoGuard refused a file with an unsafe name ({name!r}). Nothing was "
                          "changed.")
    return name


def _from_fetch_error(e: setup_fetch.FetchError) -> SourceError:
    return SourceError(str(e), e.kind or "")


class LocalFolderSource:
    def __init__(self, path):
        self.path = Path(path)
        self.label = f"the update folder {self.path}"

    def refresh(self) -> None:
        if not self.path.is_dir():
            raise SourceError(f"The update folder {self.path} does not exist.", "not_published")

    def fetch_bytes(self, name: str, max_size: int = META_MAX) -> bytes | None:
        p = self.path / _safe_name(name)
        if not p.is_file():
            return None
        if p.stat().st_size > max_size:
            raise SourceError(f"{name} in {self.label} is far bigger than expected, so it was not "
                              "used. Nothing was changed.", "too_big")
        return p.read_bytes()

    def download(self, name: str, dest: Path, entry: dict, progress=None) -> Path:
        src = self.path / _safe_name(name)
        if not src.is_file():
            raise SourceError(f"{self.label} has no file named {name}. Nothing was changed.", "missing")
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(dest.name + ".part")
        limit = int(entry["length"])
        with open(src, "rb") as fin, open(part, "wb") as fout:
            copied = 0
            for block in iter(lambda: fin.read(1 << 20), b""):
                copied += len(block)
                if copied > limit:
                    break
                fout.write(block)
        if copied > limit:
            part.unlink(missing_ok=True)
            raise SourceError(setup_fetch.TOO_BIG_DOWNLOAD, "too_big")
        os.replace(part, dest)
        return dest


class GitHubReleaseSource:
    def __init__(self, repo: str, api_base: str = "https://api.github.com"):
        self.repo = repo
        self.api_base = api_base.rstrip("/")
        self.label = f"github.com/{repo}"
        self._assets: dict[str, dict] | None = None
        self.tag = ""

    def refresh(self) -> None:
        url = f"{self.api_base}/repos/{self.repo}/releases/latest"
        try:
            with setup_fetch._open(url, {"Accept": "application/vnd.github+json"}) as resp:
                raw = resp.read(META_MAX + 1)
        except setup_fetch.FetchError as e:
            if e.kind == "http" and e.code == 404:          # no release yet (or no repo): normal
                raise SourceError(NOT_PUBLISHED, "not_published") from e
            raise _from_fetch_error(e) from e
        try:
            release = json.loads(raw.decode("utf-8"))
            assets = {a["name"]: a for a in release.get("assets", []) if isinstance(a, dict)}
        except (ValueError, KeyError, AttributeError) as e:
            raise SourceError("GitHub sent an answer TacoGuard could not read. Nothing was "
                              "changed.") from e
        self.tag = str(release.get("tag_name") or "")
        self._assets = assets

    def _asset(self, name: str) -> dict | None:
        if self._assets is None:
            self.refresh()
        return self._assets.get(_safe_name(name))

    def fetch_bytes(self, name: str, max_size: int = META_MAX) -> bytes | None:
        asset = self._asset(name)
        if asset is None:
            return None
        if int(asset.get("size") or 0) > max_size:
            raise SourceError(f"{name} in the release is far bigger than expected, so it was not "
                              "used. Nothing was changed.", "too_big")
        try:
            with setup_fetch._open(asset["browser_download_url"]) as resp:
                data = resp.read(max_size + 1)
        except setup_fetch.FetchError as e:
            raise _from_fetch_error(e) from e
        if len(data) > max_size:
            raise SourceError(f"{name} in the release is far bigger than expected, so it was not "
                              "used. Nothing was changed.", "too_big")
        return data

    def download(self, name: str, dest: Path, entry: dict, progress=None) -> Path:
        asset = self._asset(name)
        if asset is None:
            raise SourceError(f"The release on {self.label} has no file named {name}. Nothing was "
                              "changed.", "missing")
        try:
            return setup_fetch._download(asset["browser_download_url"], Path(dest), entry["sha256"],
                                         progress or (lambda _m: None), name,
                                         max_bytes=int(entry["length"]))
        except setup_fetch.FetchError as e:
            raise _from_fetch_error(e) from e
