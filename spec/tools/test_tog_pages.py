"""The ToG 1.0 pages are exactly what tog_pages.py builds from the fixed text, and show its hash.
Run: python -m pytest spec/tools/test_tog_pages.py"""
import hashlib
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tog_pages as t  # noqa: E402

TEXT = (t.DIR / "legal-code.txt").read_bytes()
H = hashlib.sha256(TEXT).hexdigest()


def test_the_committed_pages_are_what_the_tool_builds():
    assert (t.DIR / "index.html").read_text(encoding="utf-8") == t.legal_page()
    assert (t.DIR / "deed.html").read_text(encoding="utf-8") == t.deed_page()


def test_both_pages_and_the_deed_show_the_hash_of_the_plain_text():
    assert t.sha256() == H
    for page in ("index.html", "deed.html"):
        assert f"SHA-256 <span>{H}</span>" in (t.DIR / page).read_text(encoding="utf-8"), page
    assert (t.DIR / "deed.md").read_text(encoding="utf-8").endswith(
        f"Legal code: ToG 1.0 public draft 1, sha256 {H}, at https://pregen.org/tog.\n")   # the hash's own text


def test_public_draft_1_with_its_two_brackets_as_written_and_labelled_on_both_pages():
    text = TEXT.decode()
    assert H == "b5ca28ccaeeecf3be03e7532b3460ff2d0d696c2f72cc7af1cff5ef5cdd178e4" and len(TEXT) == 46921
    assert text.startswith("## ToG 1.0 legal code\n\nCopyright 2026 Valerii Egorov (Pastheroza). ")
    assert '(o) "Steward" means the person or organisation that publishes this Licence at https://pregen.org/tog.' in text
    assert re.findall(r"\[[^\]]*\]", text) == ["[hash]", "[For counsel: child-performer laws may add duties.]"]
    for page in ("index.html", "deed.html"):
        html = (t.DIR / page).read_text(encoding="utf-8")
        assert html.count('id="draft"') == 1 and "ToG 1.0 public draft 1" in html and "Not in force" in html, page
        assert "covered by" not in html, page        # §16(a): the final hash is taken once the brackets are completed
        assert "— PRE-GEN</title>" in html and "ToG Protocol" not in html, page   # the protocol is PRE-GEN Protocol (2026-11-12)


def test_extract_follows_the_recipe_printed_in_the_source(tmp_path, monkeypatch):
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir(), out.mkdir()
    (src / "ToG-1.0-legal-code.md").write_text("# head\n\nnot hashed\n\nLegal code begins\n\n## ToG 1.0 legal code\n\n"
                                               "(a) [hash] stays.\n\nLegal code ends\n\ntrailer\n", encoding="utf-8")
    (src / "ToG-1.0-deed.md").write_text("# ToG 1.0 deed\n\nversion [n], sha256 [hash], of a Statement\n\n"
                                         "Legal code: ToG-1.0, sha256 [hash], at https://pregen.org/tog.\n", encoding="utf-8")
    monkeypatch.setattr(t, "DIR", out)
    t.extract(src)
    body = b"## ToG 1.0 legal code\n\n(a) [hash] stays.\n"
    assert (out / "legal-code.txt").read_bytes() == body
    deed = (out / "deed.md").read_text(encoding="utf-8")
    assert deed.endswith(f"Legal code: ToG 1.0 public draft 1, sha256 {hashlib.sha256(body).hexdigest()}, at https://pregen.org/tog.\n")
    assert "version [n], sha256 [hash], of a Statement" in deed       # the model clause keeps its own blanks
    (src / "ToG-1.0-legal-code.md").write_text("Legal code begins\n## x\n\nLegal code ends\n", encoding="utf-8")
    with pytest.raises(AssertionError):
        t.extract(src)


@pytest.mark.parametrize("bad", [b"\n## x\n", b"## x\n\n", b"## x \n", b"## x\r\n", b"## x", "## é\n".encode()])
def test_a_text_not_in_the_hashed_form_is_refused(tmp_path, monkeypatch, bad):
    (tmp_path / "legal-code.txt").write_bytes(bad)
    monkeypatch.setattr(t, "DIR", tmp_path)
    with pytest.raises(AssertionError):
        t.legal_text()


@pytest.mark.parametrize("bad", ["* a star list", "para\nand a second line", "1. one\n3. three", "| a |\n| b |"])
def test_a_markdown_shape_the_sources_do_not_use_is_refused(bad):
    with pytest.raises(AssertionError):
        t.markdown(bad)


def test_the_shapes_the_sources_use():
    assert t.markdown("### Section 2. The Statement") == '<h3 id="section-2">Section 2. The Statement</h3>'
    assert t.markdown("1. `a` & b\n2. **c**") == "<ol>\n<li><code>a</code> &amp; b</li>\n<li><strong>c</strong></li>\n</ol>"
    assert t.markdown("> one\n>\n> *two*") == "<blockquote>\n<p>one</p>\n<p><em>two</em></p>\n</blockquote>"
    assert "<th>A</th>" in t.markdown("| A |\n|---|\n| b |") and t.markdown("- x") == "<ul>\n<li>x</li>\n</ul>"
