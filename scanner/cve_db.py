import json
import os
from typing import List, Dict, Optional

_CVE_CACHE: Optional[List[Dict]] = None

def load_cve_db(db_path: str = None) -> List[Dict]:
    """
    Load CVE definitions from a local JSON file.
    Returns an empty list if file is missing or invalid.
    """
    global _CVE_CACHE
    if _CVE_CACHE is not None:
        return _CVE_CACHE

    if db_path is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        db_path = os.path.join(base_dir, "data", "cve_db.json")

    if not os.path.exists(db_path):
        print(f"[!] CVE DB not found at {db_path}. CVE correlation will be skipped.")
        _CVE_CACHE = []
        return _CVE_CACHE

    try:
        with open(db_path, "r") as f:
            _CVE_CACHE = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load CVE DB: {e}")
        _CVE_CACHE = []

    return _CVE_CACHE
