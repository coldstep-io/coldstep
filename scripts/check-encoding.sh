#!/usr/bin/env bash
# check-encoding.sh — scan tracked text-like sources for known mojibake byte sequences,
# strict UTF-8 validity, UTF-8 encoding of U+FFFD (replacement character), which usually
# indicates corrupt UTF-8 or shell/gh mangling (e.g. PowerShell --body "..." to gh).
#
# Mojibake: em-dash U+2014 (UTF-8: E2 80 94) corrupting to CE 93 C3 87 C3 B6 (Windows-1252 path).
# Replacement: U+FFFD UTF-8 EF BF BD — almost never intentional in repo sources.
#
# Glob list: keep scan_python_combined, scan_grep_moj, and scan_grep_repl in sync.
set -euo pipefail

# Mojibake bytes (must match CI guard in AGENTS.md / knowledge/wiki).
MOJ=$'\xce\x93\xc3\x87\xc3\xb6'

# Text extensions to scan (excludes binaries like .png, .wasm); includes bpf/*.h, *.inc, *.c
ENCODING_SCAN_GLOBS=(
  '*.go' '*.sh' '*.bash'
  '*.yml' '*.yaml'
  '*.ts' '*.tsx' '*.js' '*.mjs' '*.cjs'
  '*.md' '*.mdc'
  '*.c' '*.h' '*.inc'
  '*.json' '*.toml' '*.mod'
  '*.css' '*.html' '*.svg' '*.txt'
  '*.ps1'
)

scan_python_combined() {
  git ls-files -- "${ENCODING_SCAN_GLOBS[@]}" | python3 -c "
import sys
moj = bytes([0xce, 0x93, 0xc3, 0x87, 0xc3, 0xb6])
repl = bytes([0xef, 0xbf, 0xbd])
bad_moj, bad_repl, bad_decode = [], [], []
bpf_mangle_files = []
# U+FFFD + \"pf\" / \"BPF\" = common PowerShell/gh paste damage (shows like \" \\ufffd pf\" in viewers)
mangle_markers = (repl + b'pf', repl + b' pf', repl + b'BPF', repl + b' BPF')
for f in sys.stdin.read().splitlines():
    try:
        raw = open(f, 'rb').read()
    except OSError:
        continue
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError as e:
        bad_decode.append((f, str(e)))
    if moj in raw:
        bad_moj.append(f)
    if repl in raw:
        bad_repl.append(f)
        if any(m in raw for m in mangle_markers):
            bpf_mangle_files.append(f)
err = False
if bad_moj:
    err = True
    print('::error::Mojibake em-dash sequence (bytes CE93 C387 C3B6) found in tracked files:', file=sys.stderr)
    print('\n'.join(bad_moj), file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix: replace with proper em-dash (U+2014, UTF-8 E2 80 94) or ASCII \" - \".', file=sys.stderr)
if bad_repl:
    err = True
    print('::error::Unicode replacement character U+FFFD (UTF-8 bytes EF BF BD) found - corrupt UTF-8 or paste/shell damage:', file=sys.stderr)
    print('\n'.join(bad_repl), file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix: re-save as UTF-8. For gh PR text use: gh pr create/edit --body-file .github/pr-bodies/your.md (see .github/pr-bodies/README.md).', file=sys.stderr)
if bpf_mangle_files:
    print('::warning::Likely mangled \"BPF\"/\"eBPF\" (U+FFFD before pf/BPF) in:', file=sys.stderr)
    print('\n'.join(sorted(set(bpf_mangle_files))), file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix: type BPF and eBPF as plain ASCII; never use gh --body \"...\" from PowerShell for long text.', file=sys.stderr)
if bad_decode:
    err = True
    print('::error::File is not valid UTF-8 (strict decode failed):', file=sys.stderr)
    for f, msg in bad_decode:
        print(f'  {f}: {msg}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix: re-save as UTF-8; on Windows use UTF-8 for gh PR body files.', file=sys.stderr)
sys.exit(1 if err else 0)
"
}

scan_grep_moj() {
  git ls-files -- "${ENCODING_SCAN_GLOBS[@]}" \
    | xargs -r grep -Frl "${MOJ}" 2>/dev/null || true
}

# Scan for UTF-8 U+FFFD without Python (best-effort): grep fixed-string binary-ish
scan_grep_repl() {
  # shellcheck disable=SC2059
  git ls-files -- "${ENCODING_SCAN_GLOBS[@]}" \
    | while read -r f; do
        grep -Fq "$(printf '\357\277\275')" "$f" 2>/dev/null && echo "$f"
      done || true
}

use_python=false
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  use_python=true
fi

if [ "${use_python}" = true ]; then
  if ! scan_python_combined; then
    exit 1
  fi
else
  hits=$(scan_grep_moj)
  if [ -n "${hits}" ]; then
    echo "::error::Mojibake em-dash (bytes CE93 C387 C3B6) found in tracked files:"
    echo "${hits}"
    exit 1
  fi
  hits_repl=$(scan_grep_repl)
  if [ -n "${hits_repl}" ]; then
    echo "::error::Unicode replacement U+FFFD (UTF-8 EF BF BD) found (install python3 for full encoding scan):"
    echo "${hits_repl}"
    exit 1
  fi
  echo "::warning::python3 unavailable — only mojibake + grep replacement scan ran; install python3 for combined CI parity."
fi

echo "encoding check passed — scanned text globs (see ENCODING_SCAN_GLOBS in script); no mojibake or U+FFFD replacement sequences found"
