#!/usr/bin/env python3
"""Build the ToG 1.0 pages of pregen.org from their sources, so the page shows exactly the fixed text and its hash.

    tog/1.0/legal-code.txt  the legal code: the lines between "Legal code begins" and "Legal code ends", those lines
                            and the blank lines next to them excluded, UTF-8, NFC, one LF per line, no trailing space,
                            no blank last line, the bracketed places as written. Its SHA-256 is the licence's hash.
    tog/1.0/deed.md         the deed (a plain-language summary; not hashed, not the licence)

    python3 -I spec/tools/tog_pages.py      writes tog/1.0/index.html (/tog/1.0) and tog/1.0/deed.html (/tog/1.0/deed)
    python3 -I spec/tools/tog_pages.py --from DIR   first re-extracts both sources from DIR/ToG-1.0-legal-code.md
                                            (by the recipe printed at its top) and DIR/ToG-1.0-deed.md ([hash] filled,
                                            labelled as public draft 1's)

ToG 1.0 public draft 1 (11 November 2026): one common text for everyone; a person attaches it with their own short card.
spec/tools/test_tog_pages.py checks the committed pages are what this prints and that the text keeps its form.
"""
import hashlib
import html
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "tog" / "1.0"
URL = "https://www.pregen.org/tog/1.0"
LABEL = "ToG 1.0 public draft 1"     # every page and card that cites the text says which text it is


def extract(src: Path):
    """The sources as written -> tog/1.0/legal-code.txt and tog/1.0/deed.md. The hashed part: the lines between the
    whole lines `Legal code begins` and `Legal code ends`, those two and the blank line next to each excluded."""
    lines = (src / "ToG-1.0-legal-code.md").read_text(encoding="utf-8").split("\n")
    i, j = lines.index("Legal code begins"), lines.index("Legal code ends")
    assert lines[i + 1] == "" and lines[j - 1] == "", "a blank line next to each marker"
    (DIR / "legal-code.txt").write_bytes(("\n".join(lines[i + 2:j - 1]) + "\n").encode("utf-8"))
    deed = (src / "ToG-1.0-deed.md").read_text(encoding="utf-8")
    assert deed.count("Legal code: ToG-1.0, sha256 [hash],") == 1, "the deed names the legal code's hash once"
    # The hash is public draft 1's, not the final ToG 1.0's (its §16(a)): the line names the text it is the hash of.
    (DIR / "deed.md").write_text(deed.replace("ToG-1.0, sha256 [hash],", f"{LABEL}, sha256 {sha256()},"), encoding="utf-8")


def legal_text() -> str:
    """The fixed text, refused if it is not in the hashed form (§ docstring)."""
    t = (DIR / "legal-code.txt").read_bytes().decode("utf-8")
    lines = t.split("\n")
    assert t.endswith("\n") and lines[-2] != "" and lines[0] != "", "no blank first or last line, LF-terminated"
    assert unicodedata.normalize("NFC", t) == t and "\r" not in t, "NFC, LF only"
    assert not any(line != line.rstrip(" \t") for line in lines), "no trailing spaces or tabs"
    return t


def sha256() -> str:
    return hashlib.sha256(legal_text().encode("utf-8")).hexdigest()


def inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    return re.sub(r"(?<![*\w])\*([^*]+)\*(?![*\w])", r"<em>\1</em>", s)


def slug(heading: str) -> str:
    m = re.match(r"(Part|Section) (\d+)", heading)
    return f"{m[1].lower()}-{m[2]}" if m else re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")


def markdown(text: str) -> str:
    """The Markdown the two sources use, and nothing else: a block of another shape is refused, never guessed."""
    out = []
    for block in re.split(r"\n\s*\n", text.strip("\n")):
        lines = block.split("\n")
        if len(lines) == 1 and (m := re.match(r"(#{1,3}) (.+)", lines[0])):
            n = len(m[1]) + (1 if len(m[1]) == 1 else 0)          # the page has its own h1
            out.append(f'<h{n} id="{slug(m[2])}">{inline(m[2])}</h{n}>')
        elif all(re.match(r"\d+\. ", ln) for ln in lines):
            assert [int(ln.split(".")[0]) for ln in lines] == list(range(1, len(lines) + 1)), block
            out.append("<ol>\n" + "\n".join(f"<li>{inline(ln.split('. ', 1)[1])}</li>" for ln in lines) + "\n</ol>")
        elif all(ln.startswith("- ") for ln in lines):
            out.append("<ul>\n" + "\n".join(f"<li>{inline(ln[2:])}</li>" for ln in lines) + "\n</ul>")
        elif all(ln.startswith(">") for ln in lines):
            paras = "\n".join(ln[1:].lstrip() for ln in lines).split("\n\n")
            out.append("<blockquote>\n" + "\n".join(f"<p>{inline(p)}</p>" for p in paras) + "\n</blockquote>")
        elif all(ln.startswith("|") for ln in lines):
            cells = [[c.strip() for c in ln.strip("|").split("|")] for ln in lines]
            assert all(re.fullmatch(r"-+", c) for c in cells[1]), block
            row = lambda tag, r: "<tr>" + "".join(f"<{tag}>{inline(c)}</{tag}>" for c in r) + "</tr>"  # noqa: E731
            out.append('<div class="table"><table>\n<thead>' + row("th", cells[0]) + "</thead>\n<tbody>\n"
                       + "\n".join(row("td", r) for r in cells[2:]) + "\n</tbody></table></div>")
        else:
            assert len(lines) == 1 and not re.match(r"[#>|]|[-*+] |\d+\. ", lines[0]), block
            out.append(f"<p>{inline(lines[0])}</p>")
    return "\n".join(out)


HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — PRE-GEN</title>
<meta name="description" content="{description}">
<link rel="canonical" href="{url}">
<link rel="icon" type="image/png" href="/assets/pregen-logo.png">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<link rel="stylesheet" href="/styles.css">
<link rel="stylesheet" href="/tog.css">
<script src="/theme.js"></script>
<script src="/site.js" defer></script>
</head>
<body>
<header class="top"><div class="wrap">
<a class="mark" href="/homepage"><img src="/assets/pregen-mark.png" width="32" height="32" alt="PRE-GEN"></a>
<button class="menu-btn" type="button" aria-controls="site-menu" aria-expanded="false" aria-label="Open menu"><span></span><span></span></button>
<div class="menu" id="site-menu">
<nav aria-label="Main"><a href="/tog">Create your ToG</a><a href="/connect">Connect your AI</a><a href="/create-registry">Create a registry</a><a href="/docs">How it works</a><a href="/registries">Registries</a><a href="/lookup">Look up a code</a><a href="/faq">FAQ</a><a href="https://github.com/Pastheroza/PRE-GEN-site">GitHub</a></nav>
</div>
</div></header>
<main><div class="wrap tl-wrap">
"""
FOOT = """</div></main>
<footer class="foot"><div class="wrap">
<div class="foot-top">
<div class="foot-brand"><a class="mark" href="/homepage"><img src="/assets/pregen-mark.png" width="56" height="56" alt="PRE-GEN"></a><p>Pre-Generative Authorization Protocol. AI asks before it generates a real person.</p></div>
<nav class="foot-cols" aria-label="Site">
<div><p class="foot-h">Start</p><a href="/connect">Connect your AI</a><a href="/create-registry">Create a registry</a><a href="/lookup">Look up a code</a></div>
<div><p class="foot-h">Learn</p><a href="/docs">How it works</a><a href="/docs/two-layers">Two layers</a><a href="/faq">FAQ</a><a href="/llms.txt">llms.txt</a></div>
<div><p class="foot-h">Project</p><a href="/registries">Registries</a><a href="https://github.com/Pastheroza/PRE-GEN-site">GitHub</a><a href="https://github.com/Pastheroza/PRE-GEN-site/tree/main/spec">Specification</a><a href="/support">Support</a></div>
<div><p class="foot-h">Legal</p><a href="/legal">Legal</a><a href="/contact">Contact</a></div>
</nav>
</div>
<div class="foot-bottom"><p>&copy; 2026 Valerii Egorov. Open standard, Apache-2.0. Not owned by any registry, including PRAMPTA.</p><p class="foot-ver">v5</p></div>
</div></footer>
</body>
</html>
"""
# The source's own status line (ToG-1.0-legal-code.md, above the hashed part), shown on both pages. Its §16(a): the
# final ToG 1.0 hash is taken once every bracket is completed, so this public-draft hash is not it.
DRAFT = ('<p class="tl-steward" id="draft"><b>' + LABEL + '</b>, 11 November 2026. Draft for review by qualified '
         "counsel. Not legal advice. Not in force. Text in square brackets (the hash of profile <code>likeness/2</code> "
         "in Section 1(m) and a note for counsel in Section 5(d)) is for counsel or the Steward to complete. Under "
         "Section 16(a) the final ToG 1.0 hash is taken after that, so it will differ from this public-draft hash. "
         "Steward URL: https://pregen.org/tog.</p>")


def hash_block(h: str) -> str:
    return (f'<p class="tl-hash mono">{LABEL} · SHA-256 <span>{h}</span></p>\n'
            '<p class="tl-links"><a href="/tog/1.0/legal-code.txt">The hashed text, plain</a>'
            '<a href="/tog/1.0">Legal code</a><a href="/tog/1.0/deed">Deed</a><a href="/tog">Create your ToG</a></p>')


def legal_page() -> str:
    h = sha256()
    return (HEAD.format(title="ToG 1.0 legal code", url=URL,
                        description="Terms of Generation 1.0: one common licence text for a person's likeness and voice, "
                                    "identical for everyone, fixed by its SHA-256.")
            + '<p class="tl-kicker mono">TERMS OF GENERATION · LEGAL CODE · ToG 1.0 PUBLIC DRAFT 1</p>\n'
            + "<h1>Terms of Generation 1.0</h1>\n"
            + '<p class="tl-lede">One common text, the same for everyone. A person applies it with their own short card: '
              "their ToG code, their answers and a link to this page.</p>\n"
            + hash_block(h) + "\n" + DRAFT + "\n"
            + '<article class="tl-text" id="legal-code">\n' + markdown(legal_text()) + "\n</article>\n" + FOOT)


def deed_page() -> str:
    h = sha256()
    src = (DIR / "deed.md").read_text(encoding="utf-8")
    title, body = src.split("\n", 1)
    assert title == "# ToG 1.0 deed" and "[hash]" not in body.split("\n")[-2], "the deed names the hash, filled in"
    return (HEAD.format(title="ToG 1.0 deed", url=URL + "/deed",
                        description="Terms of Generation 1.0 in plain words: a summary of the legal code, not the licence.")
            + '<p class="tl-kicker mono">TERMS OF GENERATION · DEED · ToG 1.0 PUBLIC DRAFT 1</p>\n'
            + "<h1>ToG 1.0 deed</h1>\n" + hash_block(h) + "\n" + DRAFT + "\n"
            + '<article class="tl-text">\n' + markdown(body) + "\n</article>\n" + FOOT)


def main():
    if sys.argv[1:2] == ["--from"]:
        extract(Path(sys.argv[2]))
    (DIR / "index.html").write_text(legal_page(), encoding="utf-8")
    (DIR / "deed.html").write_text(deed_page(), encoding="utf-8")
    print(sha256())


if __name__ == "__main__":
    sys.exit(main())
