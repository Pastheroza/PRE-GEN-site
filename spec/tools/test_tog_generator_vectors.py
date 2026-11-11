"""spec/test-vectors/tog-generator.json is exactly what tog_generator_vectors.py prints (about 25 s: the reference's
exhaustive self-check runs first). Run: python -m pytest spec/tools/test_tog_generator_vectors.py"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def test_vectors_regenerate_byte_for_byte():
    out = subprocess.run([sys.executable, "-I", str(HERE / "tog_generator_vectors.py")], capture_output=True, check=True)
    assert out.stdout == (HERE.parent / "test-vectors" / "tog-generator.json").read_bytes()
