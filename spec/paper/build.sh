#!/bin/sh
# Build the Zenodo PDF from pre-gen-v<N>.html with Chrome's print engine
# (A4, Times/Courier from macOS — the same fonts as versions 1–4).
#   spec/paper/build.sh 5                          -> draft (concept DOI, "Draft")
#   DOI=10.5281/zenodo.NNN spec/paper/build.sh 5   -> the version as published
set -eu
V=${1:?version number}
HERE=$(cd "$(dirname "$0")" && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
DATE=$(sed -n 's/.*data-date="\([^"]*\)".*/\1/p' "$HERE/pre-gen-v$V.html" | head -1)
if [ -n "${DOI:-}" ]; then
  DOI_LINE="DOI: $DOI"; VER_LINE="Version $V · $DATE"
else
  DOI_LINE="Concept DOI: 10.5281/zenodo.20129901"; VER_LINE="Version $V · DRAFT, not yet published · $DATE"
fi
TMP="$HERE/.build-v$V.html"
sed -e "s|{{DOI_LINE}}|$DOI_LINE|" -e "s|{{VER_LINE}}|$VER_LINE|" "$HERE/pre-gen-v$V.html" > "$TMP"
"$CHROME" --headless --disable-gpu --no-pdf-header-footer --run-all-compositor-stages-before-draw \
  --print-to-pdf="$HERE/../PRE-GEN-v$V.pdf" "file://$TMP" 2>/dev/null
rm -f "$TMP"
python3 - "$HERE/../PRE-GEN-v$V.pdf" "$V" <<'PY'
import sys
from pypdf import PdfReader, PdfWriter
path, v = sys.argv[1], sys.argv[2]
w = PdfWriter(clone_from=PdfReader(path))
w.add_metadata({"/Title": "PRE-GEN — Technical Specification", "/Author": "Valerii Egorov (Pastheroza)",
                "/Subject": f"PRE-GEN version {v}", "/Creator": "", "/Keywords": "PRE-GEN, pre-generation authorization"})
w.write(path)
PY
echo "Wrote spec/PRE-GEN-v$V.pdf"
