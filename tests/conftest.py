"""Unit tests model an x86 worker unless a test explicitly selects another ISA."""
import pytest


@pytest.fixture(autouse=True)
def deterministic_worker_arch(monkeypatch):
    monkeypatch.setattr("forge.architecture.worker_arch", lambda: "x86_64")
