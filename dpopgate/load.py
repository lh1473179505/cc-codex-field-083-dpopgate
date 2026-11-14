"""Load a DPoP request snapshot, proof, access token, replay log, keys and policy."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

class LoadError(Exception):
    pass

def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(str(exc)) from exc

def load_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise LoadError(str(exc)) from exc
