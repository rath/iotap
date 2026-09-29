# /// script
# requires-python = ">=3.9"
# dependencies = ["fonttools[woff]==4.63.0"]
# ///
"""Cuts the fonts of the Korean, Chinese and Japanese pages down to the characters those pages use.

The site's Latin faces ship as Latin subsets. Pretendard, Noto Sans SC and Pretendard JP hold
thousands of Hangul syllables, Hanzi and kanji, megabytes each, of which a page uses a few hundred,
so the face of each page
holds only the characters its pages show, plus printable ASCII so that its Latin matches. That
means the fonts must be cut again whenever the text of those pages changes, from the full fonts,
which the repository does not keep:

    uv run scripts/site/subset_fonts.py --pretendard PretendardVariable.ttf \\
        --noto-sans-sc NotoSansSC-VF.ttf --pretendard-jp PretendardJPVariable.ttf

PretendardVariable.ttf and PretendardJPVariable.ttf are public/variable/*.ttf in the Pretendard and
PretendardJP release zips (https://github.com/orioncactus/pretendard/releases, v1.3.9 when this
was written) and NotoSansSC-VF.ttf is Sans/Variable/TTF/Subset/NotoSansSC-VF.ttf in the noto-cjk
repository (https://github.com/notofonts/noto-cjk). Each option alone cuts that font only.

A character a page gains that its font lacks falls back to a system font, which is easy to miss,
so this fails when a font cannot supply a character of its pages.
"""

from __future__ import annotations

import argparse
import string
import sys
from html.parser import HTMLParser
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
FONTS = DOCS / "assets" / "fonts"

# The pages that show each font, and the file it is written to. The link-preview card of each
# language is rendered from its own page, which shows the same headline.
FACES = {
    "pretendard": {
        "pages": [DOCS / "ko" / "index.html", DOCS / "assets" / "og-card-ko.html"],
        "out": FONTS / "pretendard-ko-wght.woff2",
    },
    "noto_sans_sc": {
        "pages": [DOCS / "zh" / "index.html", DOCS / "assets" / "og-card-zh.html"],
        "out": FONTS / "noto-sans-sc-zh-wght.woff2",
    },
    "pretendard_jp": {
        "pages": [DOCS / "ja" / "index.html", DOCS / "assets" / "og-card-ja.html"],
        "out": FONTS / "pretendard-jp-ja-wght.woff2",
    },
}

# Attributes whose values the page shows: data-label becomes the row labels of the comparison
# table on narrow screens, data-copied the words of a copy button once it has copied.
SHOWN_ATTRIBUTES = ("data-label", "data-copied")


class Shown(HTMLParser):
    """Collects the characters a page shows in its own language: the text of its body outside
    scripts, styles and elements marked as another language, such as the links to the other
    languages, which a system font sets, and the attribute values its style sheet or script puts
    on the page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chars: set[str] = set()
        self.lang = ""
        self.hiding: list[str] = []
        self.in_body = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lang = dict(attrs).get("lang")
        if tag == "html":
            self.lang = (lang or "").split("-")[0]
        elif tag == "body":
            self.in_body = True
        elif tag in ("script", "style") or (lang and lang.split("-")[0] != self.lang):
            self.hiding.append(tag)
        for name, value in attrs:
            if name in SHOWN_ATTRIBUTES and value:
                self.chars.update(value)

    def handle_endtag(self, tag: str) -> None:
        if self.hiding and self.hiding[-1] == tag:
            self.hiding.pop()

    def handle_data(self, data: str) -> None:
        if self.in_body and not self.hiding:
            self.chars.update(data)


def shown_characters(pages: list[Path]) -> set[str]:
    chars: set[str] = set()
    for page in pages:
        parser = Shown()
        parser.feed(page.read_text(encoding="utf-8"))
        chars |= parser.chars
    chars |= set(string.printable)
    return {c for c in chars if not c.isspace() or c == " "}


def cut(source: Path, chars: set[str], out: Path) -> tuple[int, int]:
    """Writes the subset of `source` holding `chars` to `out`, as woff2, keeping every name of the
    font so that its license and reserved name travel with it. Returns the counts of the glyphs
    kept and of the bytes written."""
    options = subset.Options()
    options.flavor = "woff2"
    options.name_IDs = ["*"]
    options.hinting = False
    options.desubroutinize = True
    font = TTFont(str(source))
    subsetter = subset.Subsetter(options)
    subsetter.populate(text="".join(sorted(chars)))
    subsetter.subset(font)
    out.parent.mkdir(parents=True, exist_ok=True)
    font.save(str(out))
    return len(font.getGlyphOrder()), out.stat().st_size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pretendard", type=Path, help="the full PretendardVariable.ttf")
    parser.add_argument("--noto-sans-sc", type=Path, help="the full NotoSansSC-VF.ttf")
    parser.add_argument("--pretendard-jp", type=Path, help="the full PretendardJPVariable.ttf")
    args = parser.parse_args()
    sources = {name: getattr(args, name) for name in FACES if getattr(args, name)}
    if not sources:
        parser.error("name at least one font to cut")

    failed = False
    for name, source in sources.items():
        face = FACES[name]
        chars = shown_characters(face["pages"])
        cmap = TTFont(str(source)).getBestCmap()
        missing = sorted(c for c in chars if ord(c) not in cmap)
        if missing:
            print(
                f"{source.name} lacks {len(missing)} of the characters its pages show: "
                f"{''.join(missing)}",
                file=sys.stderr,
            )
            failed = True
            continue
        glyphs, size = cut(source, chars, face["out"])
        pages = ", ".join(str(p.relative_to(ROOT)) for p in face["pages"])
        print(
            f"{face['out'].relative_to(ROOT)}: {len(chars)} characters of {pages}; "
            f"{glyphs} glyphs, {size:,} bytes"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
