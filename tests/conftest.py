import pytest

from src.engine.pipeline import Engine
from src.engine.policy import PolicyBundle


@pytest.fixture
def engine() -> Engine:
    return Engine()


@pytest.fixture
def policy() -> PolicyBundle:
    return PolicyBundle.default()
