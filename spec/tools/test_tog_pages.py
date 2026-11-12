"""The ToG 1.0 pages are exactly what tog_pages.py builds from the fixed text, and show its hash.
Run: python -m pytest spec/tools/test_tog_pages.py"""
import hashlib
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
        f"Legal code: ToG-1.0, sha256 {H}, at https://www.pregen.org/tog/1.0.\n")


def test_the_steward_places_stay_as_written_inside_the_hash_and_are_marked_once_outside():
    text = TEXT.decode()
    assert text.startswith("## ToG 1.0 legal code\n\nCopyright [year] [Steward]. ")
    assert '(o) "Steward" means the organisation that publishes this Licence at [URL].' in text
    page = (t.DIR / "index.html").read_text(encoding="utf-8")
    assert page.count('id="steward"') == 1 and "Copyright [year] [Steward]." in page
    assert "Draft for review" not in page + (t.DIR / "deed.html").read_text(encoding="utf-8")


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
