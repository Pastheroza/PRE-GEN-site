"""Design limits of the signed answer and the provider gate, pinned so a change that crosses one fails here.

- A signed answer (pg.answer.v1) carries no policy, rules or terms digest, no epoch, no rules version, no ledger
  reference, and nothing about the model or preprocessing; `basis.rule` is a name, never a hash of a text.
- The gate never compares policy versions or epochs: it checks request_id, lifetime, signature, revocation and
  `profile` as a name. Answers that differ only in such members get the same verdict.
- The core, its extensions and profiles, the guides and the libraries hold no embeddings, face features, similarity
  scores, ledgers, wallets or a canonical subject id: identity stays distributed (anchors, the person's own
  confirmation, a per-generation decision over claims).

The earlier interface's signed decision (verify_decision / check_decision) lists some such members among those it
recognises; that list is excluded from the source scan, and the gate compares none of them.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

import pregen

ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "spec/test-vectors/answers.json").read_text())

FORBIDDEN = re.compile(
    r"embedding|similarity|face[ _-]?(feature|vector|template|match|print)|facial|biometric|blockchain"
    r"|block[ _-]?(hash|number|height)|ledger|wallet|canonical[ _-]subject|polic(y|ies)[ _-]?(digest|hash|version)"
    r"|rules?[ _-]?(text[ _-])?(hash|digest|version)|terms[ _-]?(hash|digest)|epoch|model[ _-]?(id|manifest)"
    r"|preprocess", re.I)
# Member names a signed answer must never carry, at any depth.
FORBIDDEN_MEMBER = re.compile(
    r"polic|terms|rules|epoch|version|block|chain|ledger|model|manifest|preprocess|embedding|similarity|face"
    r"|biometric|wallet|canonical", re.I)


def _without_earlier_interface_list(text):
    """Drop the earlier interface's list of recognised decision members (one literal in each library)."""
    return re.sub(r"(_UNDERSTOOD = frozenset\(\{|const UNDERSTOOD = new Set\(\[).*?(\}\)|\]\);)", "", text, flags=re.S)


def _hits(path, text):
    return [f"{path}:{n}: {m.group(0)}" for n, line in enumerate(text.splitlines(), 1) for m in FORBIDDEN.finditer(line)]


def test_the_libraries_never_use_policy_versions_epochs_ledgers_or_biometrics():
    hits = []
    for rel in ("packages/verify-py/pregen/__init__.py", "packages/verify-js/index.js", "packages/verify-js/index.d.ts"):
        hits += _hits(rel, _without_earlier_interface_list((ROOT / rel).read_text()))
    assert not hits, hits


@pytest.mark.parametrize("pattern", ["spec/PRE-GEN-CORE.md", "spec/extensions/*.md", "spec/profiles/*.md",
                                     "docs/provider.md", "docs/registry.md", "packages/registry/pregen_registry/*.py",
                                     "spec/tools/answer_vectors.py", "spec/conformance/level1/run_conformance.py"])
def test_the_core_extensions_guides_and_reference_registry_stay_within_the_limits(pattern):
    files = sorted(ROOT.glob(pattern))
    assert files, pattern
    hits = [h for f in files for h in _hits(f.relative_to(ROOT), f.read_text())]
    assert not hits, hits


def _member_names(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _member_names(v)
    elif isinstance(value, list):
        for v in value:
            yield from _member_names(v)


def check_answer_body(body):
    """What every signed answer body must satisfy; the reference registry's tests apply it to its own answers."""
    bad = [k for k in _member_names(body) if FORBIDDEN_MEMBER.search(k)]
    assert not bad, f"an answer carries {bad}"
    rule = (body.get("basis") or {}).get("rule")
    assert rule is None or not re.fullmatch(r"[0-9a-fA-F]{16,}", rule), f"basis.rule looks like a hash: {rule}"
    assert "job_hash" not in body, "an answer never repeats what job_hash stands for, nor job_hash itself"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_every_answer_vector_stays_within_the_limits(case):
    check_answer_body(case["answer"]["body"])


def _seed(name):
    return hashlib.sha256(f"pregen-answer-vector-{name}".encode()).hexdigest()


@pytest.mark.parametrize("extra", [{"policy_version": "2026-01-01"}, {"policy_version": "2031-12-31"},
                                   {"epoch": 1}, {"epoch": 7}, {"rules_text_hash": "0" * 64}])
def test_the_gate_compares_no_policy_version_or_epoch(extra):
    """Members a registry might add are never compared: the verdict is the plain allow's verdict."""
    allow = next(c for c in VECTORS["cases"] if c["name"] == "allow")
    now, d = VECTORS["now"], pregen.verify_directory(VECTORS["directory"], VECTORS["steward_public_key_hex"],
                                                     now=VECTORS["now"])
    get_json = lambda url: VECTORS["key_sets"][url]  # noqa: E731
    body = {**allow["answer"]["body"], **extra}
    answer = pregen.sign_envelope("pg.answer.v1", body, _seed("registry"))
    assert pregen.check_answer(answer, allow["request"], d, get_json, now=now)["status"] == "allow"
