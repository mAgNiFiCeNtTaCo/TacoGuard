from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from tacoguard.config import Settings  # noqa: E402
from tacoguard.store import Store  # noqa: E402


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Settings pointing at a fresh temp data folder (never the real D:\\TacoGuard)."""
    s = Settings(data_dir=str(tmp_path / "data"))
    s.ensure_dirs()
    return s


@pytest.fixture
def store(settings) -> Store:
    st = Store(settings.db_path)
    yield st
    st.close()
