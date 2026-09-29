#!/bin/sh
# Build the Zenodo PDF from pre-gen-v<N>.html with Chrome's print engine
# (A4, Times/Courier from macOS — the same fonts as versions 1–4).
#   spec/paper/build.sh 5   ->  spec/PRE-GEN-v5.pdf
set -eu
V=${1:?version number}
HERE=$(cd "$(dirname "$0")" && pwd)
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
"$CHROME" --headless --disable-gpu --no-pdf-header-footer --run-all-compositor-stages-before-draw \
  --print-to-pdf="$HERE/../PRE-GEN-v$V.pdf" "file://$HERE/pre-gen-v$V.html" 2>/dev/null
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
