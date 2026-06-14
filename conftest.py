"""Make `src/` importable in tests without an install step (mirrors the wheel layout),
and keep the suite hermetic: default the local-model semantic pass OFF so tests never
block on ollama. Runtime is unaffected (semantic defaults ON when LEAKPROOF_SEMANTIC is
unset); this only constrains the test process. Override with LEAKPROOF_SEMANTIC=1 to
exercise the live model.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("LEAKPROOF_SEMANTIC", "0")

src = Path(__file__).parent / "src"
if src.is_dir() and str(src) not in sys.path:
    sys.path.insert(0, str(src))
