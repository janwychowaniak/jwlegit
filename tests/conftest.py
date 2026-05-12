from __future__ import annotations

import asyncio

import pytest


@pytest.fixture
def fast_sleep(monkeypatch):
    """Make asyncio.sleep instant so polling loops finish quickly."""
    async def _noop(_seconds):
        return None
    monkeypatch.setattr(asyncio, "sleep", _noop)
