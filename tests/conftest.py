import json

import pytest

from engine import log


@pytest.fixture
def events(tmp_path, monkeypatch):
    """Send the response log to a temp file and return a function that reads it back."""
    path = tmp_path / "response.jsonl"
    monkeypatch.setattr(log, "LOG", path)
    return lambda: [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
