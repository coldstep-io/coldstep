#!/usr/bin/env bash
# check-encoding.sh — scan tracked source files for known mojibake byte sequences.
#
# The em-dash U+2014 (UTF-8: E2 80 94) silently corrupts into the three-codepoint
# Windows-1252 mojibake sequence (bytes CE 93 C3 87 C3 B6) when files are saved
# in a non-UTF-8 editor or copy-pasted from Windows terminals. Fail CI if found.
set -euo pipefail

# Mojibake bytes (must match CI guard in AGENTS.md / knowledge/wiki).
MOJ=$'\xce\x93\xc3\x87\xc3\xb6'

scan_python() {
  git ls-files -- '*.go' '*.sh' '*.yml' '*.yaml' '*.ts' '*.md' | python3 -c "
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
"
}

scan_grep() {
  # Single grep -rl pass across all tracked files — much faster than one grep per file.
  git ls-files -- '*.go' '*.sh' '*.yml' '*.yaml' '*.ts' '*.md' \
    | xargs grep -Frl "${MOJ}" 2>/dev/null || true
}

# Windows may advertise python3 via App Execution Alias while the stub fails at runtime.
use_python=false
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  use_python=true
fi

if [ "${use_python}" = true ]; then
  hits=$(scan_python)
else
  hits=$(scan_grep)
fi

if [ -n "${hits}" ]; then
  echo "::error::Mojibake em-dash (bytes CE93 C387 C3B6) found in tracked files:"
  echo "${hits}"
  echo ""
  echo "Fix: replace the byte sequence with the proper em-dash (U+2014, UTF-8: E2 80 94)"
  echo "     or ASCII ' - '. Use binary-safe replacement: python open(f,'rb').read().replace(bytes([0xce,0x93,0xc3,0x87,0xc3,0xb6]), chr(0x2014).encode())"
  exit 1
fi

echo "encoding check passed — no mojibake sequences found"
