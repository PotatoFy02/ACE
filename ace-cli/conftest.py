import sys
from pathlib import Path

# Makes 'from parsers.x import' work when pytest runs from ace-cli/
sys.path.insert(0, str(Path(__file__).parent))

# Makes root sweeper/, models_db, db_helpers resolvable from ace-cli/
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )