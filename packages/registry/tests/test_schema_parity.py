"""The registry validates with its own copy of the schemas (protocol._load_schemas): it must be the spec's, byte for
byte, both ways (plan §3.6)."""
from pathlib import Path

HERE = Path(__file__).resolve()
SPEC, VENDORED = HERE.parents[3] / "spec" / "schemas", HERE.parents[1] / "pregen_registry" / "schemas"


def test_vendored_schemas_are_the_spec_schemas_byte_for_byte():
    assert sorted(p.name for p in SPEC.glob("*.json")) == sorted(p.name for p in VENDORED.glob("*.json"))
    for p in SPEC.glob("*.json"):
        assert (VENDORED / p.name).read_bytes() == p.read_bytes(), p.name
