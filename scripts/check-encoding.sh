#!/usr/bin/env bash
# check-encoding.sh — scan tracked source files for known mojibake byte sequences.
#
# The em-dash U+2014 (—, UTF-8: E2 80 94) silently corrupts into the three-codepoint
# Windows-1252 mojibake sequence "ΓÇö" (bytes CE 93 C3 87 C3 B6) when files are saved
# in a non-UTF-8 editor or copy-pasted from Windows terminals. Fail CI if found.
set -euo pipefail

hits=$(git ls-files -- '*.go' '*.sh' '*.yml' '*.yaml' '*.ts' '*.md' | python3 -c "
import sys, os
moj = bytes([0xce, 0x93, 0xc3, 0x87, 0xc3, 0xb6])
bad = []
for f in sys.stdin.read().splitlines():
    try:
        if moj in open(f, 'rb').read():
            bad.append(f)
    except OSError:
        pass
print('\n'.join(bad))
")

if [ -n "$hits" ]; then
  echo "::error::Mojibake em-dash (ΓÇö, bytes CE93 C387 C3B6) found in tracked files:"
  echo "$hits"
  echo ""
  echo "Fix: replace the byte sequence with the proper em-dash '—' (U+2014, UTF-8: E2 80 94)"
  echo "     or ASCII ' - '. Use binary-safe replacement (e.g. python open(f,'rb').replace)."
  exit 1
fi

echo "encoding check passed — no mojibake sequences found"
