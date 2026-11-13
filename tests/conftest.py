import pytest

from phishdetect.config import Settings
from phishdetect.engine import Engine


@pytest.fixture(scope="session")
def offline_engine():
    return Engine(Settings.offline())
