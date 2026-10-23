"""Load the standalone Actions script without importing the CKAN extension."""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-release.py"
spec = importlib.util.spec_from_file_location("verify_release", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
