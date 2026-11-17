#!/usr/bin/env python3
"""Build the ToG 1.0 pages of pregen.org from their sources, so the page shows exactly the fixed text and its hash.

    tog/1.0/legal-code.txt  the legal code: the lines between "Legal code begins" and "Legal code ends", those lines
                            and the blank lines next to them excluded, UTF-8, NFC, one LF per line, no trailing space,
                            no blank last line, the bracketed places as written. Its SHA-256 is the licence's hash.
    tog/1.0/deed.md         the deed (a plain-language summary; not hashed, not the licence)

    python3 -I spec/tools/tog_pages.py      writes tog/1.0/index.html (/tog/1.0) and tog/1.0/deed.html (/tog/1.0/deed)
    python3 -I spec/tools/tog_pages.py --from DIR   first re-extracts both sources from DIR/ToG-1.0-legal-code.md
                                            (by the recipe printed at its top) and DIR/ToG-1.0-deed.md ([hash] filled,
                                            labelled ToG-L 1.0)

ToG-L 1.0, Terms of Generation Licence, Version 1.0, November 2026: one common text for every person and company; each holder adds its own
appendices after it.
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
LABEL = "ToG-L 1.0"     # every page and card that cites the text says which text it is


def extract(src: Path):
    """The sources as written -> tog/1.0/legal-code.txt and tog/1.0/deed.md. The hashed part: the lines between the
    whole lines `Legal code begins` and `Legal code ends`, those two and the blank line next to each excluded."""
    lines = (src / "ToG-1.0-legal-code.md").read_text(encoding="utf-8").split("\n")
    i, j = lines.index("Legal code begins"), lines.index("Legal code ends")
    assert lines[i + 1] == "" and lines[j - 1] == "", "a blank line next to each marker"
    (DIR / "legal-code.txt").write_bytes(("\n".join(lines[i + 2:j - 1]) + "\n").encode("utf-8"))
    deed = (src / "ToG-1.0-deed.md").read_text(encoding="utf-8")
    assert deed.count("Legal code: ToG-L-1.0, sha256 [hash],") == 1, "the deed names the legal code's hash once"
    # The line names the text it is the hash of.
    (DIR / "deed.md").write_text(deed.replace("ToG-L-1.0, sha256 [hash],", f"{LABEL}, sha256 {sha256()},"), encoding="utf-8")


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
    m = re.match(r"(?:(Part|Section) )?(\d+)[. ]", heading)       # "Section 2. …" or "2. Statements." -> section-2
    return f"{(m[1] or 'Section').lower()}-{m[2]}" if m else re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")


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
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="wrap">
<a class="mark" href="/homepage"><img src="/assets/pregen-mark.png" width="32" height="32" alt=""><span class="mark-name">PREGEN.ORG</span></a>
<button class="menu-btn" type="button" aria-controls="site-menu" aria-expanded="false" aria-label="Open menu"><span></span><span></span></button>
<div class="menu" id="site-menu">
<nav aria-label="Main"><button class="nav-search" type="button" aria-expanded="false" aria-controls="site-search"><svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M15.5 15.5 21 21" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg><span>Search</span></button><a href="/tog/create">Create your ToG</a><a href="/tog" aria-current="page">The Licence</a><a href="/docs">How it works</a><a href="/connect">Connect your AI</a><a href="/registries">Registries</a><a href="/lookup">Look up a code</a><a href="/downloads">Downloads</a><div class="nav-group"><button class="nav-group-btn" type="button" aria-expanded="false" aria-controls="nav-more">More</button><div class="nav-group-list" id="nav-more"><a href="/create-registry">Create a registry</a><a href="/faq">FAQ</a><a href="/support">Support</a><a href="/contact">Contact</a><a href="https://github.com/Pastheroza/PRE-GEN-site">GitHub</a></div></div><a class="donate" href="/support">Donate</a></nav>
</div>
</div></header>
<main id="main"><div class="wrap tl-wrap">
"""
FOOT = """</div></main>
<nav class="ask-bar" aria-label="Ask an assistant about PRE-GEN"><a href="https://chatgpt.com/?prompt=Explain%20PRE-GEN%2C%20the%20open%20protocol%20for%20asking%20permission%20before%20AI%20generates%20a%20real%20person%2C%20character%20or%20brand.%20Read%20https%3A//www.pregen.org/llms.txt%20and%20https%3A//www.pregen.org/get-started.md%20first%2C%20then%20tell%20me%20what%20it%20does%2C%20how%20an%20AI%20service%20uses%20it%2C%20and%20what%20a%20signed%20answer%20proves." target="_blank" rel="noopener"><svg class="ask-ico" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z"/></svg>Ask ChatGPT</a><a href="https://claude.ai/new?q=Explain%20PRE-GEN%2C%20the%20open%20protocol%20for%20asking%20permission%20before%20AI%20generates%20a%20real%20person%2C%20character%20or%20brand.%20Read%20https%3A//www.pregen.org/llms.txt%20and%20https%3A//www.pregen.org/get-started.md%20first%2C%20then%20tell%20me%20what%20it%20does%2C%20how%20an%20AI%20service%20uses%20it%2C%20and%20what%20a%20signed%20answer%20proves." target="_blank" rel="noopener"><svg class="ask-ico" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="m4.7144 15.9555 4.7174-2.6471.079-.2307-.079-.1275h-.2307l-.7893-.0486-2.6956-.0729-2.3375-.0971-2.2646-.1214-.5707-.1215-.5343-.7042.0546-.3522.4797-.3218.686.0608 1.5179.1032 2.2767.1578 1.6514.0972 2.4468.255h.3886l.0546-.1579-.1336-.0971-.1032-.0972L6.973 9.8356l-2.55-1.6879-1.3356-.9714-.7225-.4918-.3643-.4614-.1578-1.0078.6557-.7225.8803.0607.2246.0607.8925.686 1.9064 1.4754 2.4893 1.8336.3643.3035.1457-.1032.0182-.0728-.164-.2733-1.3539-2.4467-1.445-2.4893-.6435-1.032-.17-.6194c-.0607-.255-.1032-.4674-.1032-.7285L6.287.1335 6.6997 0l.9957.1336.419.3642.6192 1.4147 1.0018 2.2282 1.5543 3.0296.4553.8985.2429.8318.091.255h.1579v-.1457l.1275-1.706.2368-2.0947.2307-2.6957.0789-.7589.3764-.9107.7468-.4918.5828.2793.4797.686-.0668.4433-.2853 1.8517-.5586 2.9021-.3643 1.9429h.2125l.2429-.2429.9835-1.3053 1.6514-2.0643.7286-.8196.85-.9046.5464-.4311h1.0321l.759 1.1293-.34 1.1657-1.0625 1.3478-.8804 1.1414-1.2628 1.7-.7893 1.36.0729.1093.1882-.0183 2.8535-.607 1.5421-.2794 1.8396-.3157.8318.3886.091.3946-.3278.8075-1.967.4857-2.3072.4614-3.4364.8136-.0425.0304.0486.0607 1.5482.1457.6618.0364h1.621l3.0175.2247.7892.522.4736.6376-.079.4857-1.2142.6193-1.6393-.3886-3.825-.9107-1.3113-.3279h-.1822v.1093l1.0929 1.0686 2.0035 1.8092 2.5075 2.3314.1275.5768-.3218.4554-.34-.0486-2.2039-1.6575-.85-.7468-1.9246-1.621h-.1275v.17l.4432.6496 2.3436 3.5214.1214 1.0807-.17.3521-.6071.2125-.6679-.1214-1.3721-1.9246L14.38 17.959l-1.1414-1.9428-.1397.079-.674 7.2552-.3156.3703-.7286.2793-.6071-.4614-.3218-.7468.3218-1.4753.3886-1.9246.3157-1.53.2853-1.9004.17-.6314-.0121-.0425-.1397.0182-1.4328 1.9672-2.1796 2.9446-1.7243 1.8456-.4128.164-.7164-.3704.0667-.6618.4008-.5889 2.386-3.0357 1.4389-1.882.929-1.0868-.0062-.1579h-.0546l-6.3385 4.1164-1.1293.1457-.4857-.4554.0608-.7467.2307-.2429 1.9064-1.3114Z"/></svg>Ask Claude</a><button class="ask-copy" type="button">Copy for AI</button></nav>
<footer class="foot"><div class="wrap">
<div class="foot-top">
<div class="foot-brand"><a class="mark" href="/homepage"><img src="/assets/pregen-mark.png" width="56" height="56" alt="PRE-GEN"></a><p>Pre-Generative Authorization Protocol. AI asks before it generates a real person.</p></div>
<nav class="foot-cols" aria-label="Site">
<div><p class="foot-h">Start</p><a href="/tog/create">Create your ToG</a><a href="/connect">Connect your AI</a><a href="/create-registry">Create a registry</a><a href="/lookup">Look up a code</a></div>
<div><p class="foot-h">Learn</p><a href="/tog">The Licence</a><a href="/docs">How it works</a><a href="/docs/two-layers">Two layers</a><a href="/faq">FAQ</a><a href="/llms.txt">llms.txt</a></div>
<div><p class="foot-h">Project</p><a href="/registries">Registries</a><a href="https://github.com/Pastheroza/PRE-GEN-site">GitHub</a><a href="https://github.com/Pastheroza/PRE-GEN-site/tree/main/spec">Specification</a><a href="/downloads">Downloads</a><a href="/support">Support</a></div>
<div><p class="foot-h">Legal</p><a href="/legal">Legal</a><a href="/contact">Contact</a><a href="/map">Site map</a></div>
</nav>
</div>
<div class="foot-bottom"><p>&copy; 2026 Valerii Egorov. Open standard.</p></div>
</div></footer>
</body>
</html>
"""
def hash_block(h: str) -> str:
    return (f'<p class="tl-hash mono">{LABEL} · SHA-256 <span>{h}</span></p>\n'
            '<p class="tl-links"><a href="/tog/1.0/legal-code.txt">The hashed text, plain</a>'
            '<a href="/tog/1.0">Legal code</a><a href="/tog/1.0/deed">Deed</a><a href="/downloads">PDF and examples</a>'
            '<a href="/tog/create">Create your ToG</a></p>')


def legal_page() -> str:
    h = sha256()
    return (HEAD.format(title="ToG-L 1.0 legal code", url=URL,
                        description="Terms of Generation Licence 1.0: one common licence text for a person's likeness "
                                    "and voice and for what a person or a company owns, identical for everyone, fixed by "
                                    "its SHA-256.")
            + '<p class="tl-kicker mono">TERMS OF GENERATION · LEGAL CODE · ToG-L 1.0</p>\n'
            + "<h1>Terms of Generation Licence 1.0</h1>\n"
            + '<p class="tl-lede">One common text, the same for every person and company. Each holder adds its own '
              "pages after it: its ToG code, its rules, its deals.</p>\n"
            + hash_block(h) + "\n"
            + '<article class="tl-text" id="legal-code">\n' + markdown(legal_text()) + "\n</article>\n" + FOOT)


def deed_page() -> str:
    h = sha256()
    src = (DIR / "deed.md").read_text(encoding="utf-8")
    title, body = src.split("\n", 1)
    assert title == "# ToG-L 1.0 deed" and "[hash]" not in body.split("\n")[-2], "the deed names the hash, filled in"
    return (HEAD.format(title="ToG-L 1.0 deed", url=URL + "/deed",
                        description="Terms of Generation Licence 1.0 in plain words: a summary of the legal code, not "
                                    "the licence.")
            + '<p class="tl-kicker mono">TERMS OF GENERATION · DEED · ToG-L 1.0</p>\n'
            + "<h1>ToG-L 1.0 deed</h1>\n" + hash_block(h) + "\n"
            + '<article class="tl-text">\n' + markdown(body) + "\n</article>\n" + FOOT)


def main():
    if sys.argv[1:2] == ["--from"]:
        extract(Path(sys.argv[2]))
    (DIR / "index.html").write_text(legal_page(), encoding="utf-8")
    (DIR / "deed.html").write_text(deed_page(), encoding="utf-8")
    print(sha256())


if __name__ == "__main__":
    sys.exit(main())
