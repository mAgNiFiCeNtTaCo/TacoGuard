"""The guard gives memory back by restarting itself (service.Guard._maybe_recycle)."""
from __future__ import annotations

import time

from tacoguard.guard import service
from tacoguard.store import Store


class _Stub:
    """Just enough of a Guard for _maybe_recycle: its store, the switches and request_stop."""

    def __init__(self, store, enabled=True):
        self.store = store
        self.recycle_enabled = enabled
        self.recycle = False
        self.stopped = ""
        self.RECYCLE_PRIVATE_MB = 0          # any real process is above this
        self.RECYCLE_MIN_GAP_S = service.Guard.RECYCLE_MIN_GAP_S

    def request_stop(self, why):
        self.stopped = why


def test_recycles_once_then_waits_the_gap(settings):
    store = Store(settings.db_path)
    g = _Stub(store)
    assert service.Guard._maybe_recycle(g) is True
    assert g.recycle and "memory" in g.stopped
    assert float(store.get_meta("guard_recycled_at")) <= time.time()
    g2 = _Stub(store)                        # the fresh guard, right after: no restart loop
    assert service.Guard._maybe_recycle(g2) is False and not g2.recycle


def test_no_recycle_when_off_or_under_the_limit(settings):
    store = Store(settings.db_path)
    assert service.Guard._maybe_recycle(_Stub(store, enabled=False)) is False
    g = _Stub(store)
    g.RECYCLE_PRIVATE_MB = 10**6
    assert service.Guard._maybe_recycle(g) is False and store.get_meta("guard_recycled_at") is None


def test_in_process_guard_never_recycles(settings):
    g = service.Guard(settings, Store(settings.db_path))
    assert g.recycle_enabled is False        # only main() with a --parent turns it on
