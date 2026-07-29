"""Local filesystem object store — the "local-equivalent for dev" the
spec calls for in section 4.1, standing in for S3 until a real pilot
needs it. Narrow interface on purpose: swapping in a real S3 client later
should only mean rewriting this one file, not any caller.
"""
from pathlib import Path

from db import DATA_DIR

OBJECTS_DIR = DATA_DIR / "objects"


def save_object(key: str, data: bytes) -> None:
    path = OBJECTS_DIR / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def read_object(key: str) -> bytes:
    return (OBJECTS_DIR / key).read_bytes()
