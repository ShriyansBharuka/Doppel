"""Unique identifier generation supporting deterministic seeded sequences."""

import random
from typing import Optional
import uuid

_seed: Optional[int] = None
_rng: Optional[random.Random] = None


def set_seed(seed: Optional[int]) -> None:
    """Set or clear the random seed for deterministic ID generation."""
    global _seed, _rng
    _seed = seed
    if seed is not None:
        _rng = random.Random(seed)
    else:
        _rng = None


def is_seeded() -> bool:
    """Return True if a deterministic seed is currently active."""
    return _seed is not None


def new_id() -> str:
    """Generate a 12-hex character identifier (seeded or uuid4)."""
    if _rng is not None:
        return f"{_rng.getrandbits(48):012x}"
    return uuid.uuid4().hex[:12]
