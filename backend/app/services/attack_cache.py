import json
from functools import lru_cache
from pathlib import Path

ATTACK_DATA_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "attack"
    / "enterprise-attack.json"
)


@lru_cache(maxsize=1)
def load_attack_bundle() -> dict:
    with open(ATTACK_DATA_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def get_attack_objects() -> list[dict]:
    bundle = load_attack_bundle()
    return bundle.get("objects", [])