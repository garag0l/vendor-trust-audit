from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

FIXTURE = Path(__file__).parent / "fixtures" / "account_gaad.json"
NOW = datetime(2026, 11, 25, tzinfo=UTC)


@pytest.fixture
def fixture_path() -> Path:
    return FIXTURE
