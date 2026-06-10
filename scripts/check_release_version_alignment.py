#!/usr/bin/env python3
"""
Guardrail: the agent version this commit downloads matches the version this
commit advertises — and, at release time, the tag being published.

Why this exists (v0.5.2 incident): the v0.5.2 tag was placed on a commit whose
src/shared.ts (and compiled dist/) still read COLDSTEP_BINARY_VERSION='v0.5.1',
so consumers pinning the action to the v0.5.2 tag silently ran the v0.5.1
agent. The COLDSTEP_BINARY_VERSION bump used to live in a post-tag "Train-2"
commit, which made every tag ship the previous binary by construction.

Invariant enforced (see RELEASE_PROCESS.md "Release invariant"):

  COLDSTEP_BINARY_VERSION (src/shared.ts)
    == version embedded in dist/{pre,main,post}/index.js
    == MARKETPLACE_COLDSTEP_TAG (scripts/check_workflow_action_pins.py)
    == the git tag, when --tag is passed (supply-chain-attest gate)

Run sites:
  - coldstep-ci-runner.yml action_bundle job (every PR / push): no --tag.
  - supply-chain-attest.yml (on v* tag push): --tag "$GITHUB_REF_NAME",
    failing the release BEFORE any asset is built, attested, or uploaded.
  - internal/releasecheck mirrors the no-tag checks in `go test ./...`.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

SHARED_TS = ROOT / "src" / "shared.ts"
PIN_SCRIPT = ROOT / "scripts" / "check_workflow_action_pins.py"
DIST_BUNDLES = (
    ROOT / "dist" / "pre" / "index.js",
    ROOT / "dist" / "main" / "index.js",
    ROOT / "dist" / "post" / "index.js",
)

BINARY_VERSION_RE = re.compile(
    r"^export const COLDSTEP_BINARY_VERSION = '(v[0-9]+\.[0-9]+\.[0-9]+[^']*)';$",
    re.MULTILINE,
)
MARKETPLACE_TAG_RE = re.compile(
    r'^MARKETPLACE_COLDSTEP_TAG = "(v[0-9]+\.[0-9]+\.[0-9]+[^"]*)"$',
    re.MULTILINE,
)


def fail(msg: str) -> None:
    print(f"check_release_version_alignment: {msg}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        default="",
        help="git tag being released (e.g. v0.5.3); when set, COLDSTEP_BINARY_VERSION must equal it",
    )
    args = parser.parse_args()

    exit_code = 0

    shared = SHARED_TS.read_text(encoding="utf-8")
    m = BINARY_VERSION_RE.search(shared)
    if not m:
        fail(f"{SHARED_TS.relative_to(ROOT)}: COLDSTEP_BINARY_VERSION declaration not found")
        return 1
    binary_version = m.group(1)

    # dist/ is compiled from src/ — esbuild inlines the version constant, so a
    # bumped src/shared.ts without a dist/ rebuild leaves stale bundles that
    # download the OLD agent. Substring match against the quoted literal.
    for bundle in DIST_BUNDLES:
        if not bundle.is_file():
            fail(f"{bundle.relative_to(ROOT)}: missing (run `npm run build` and commit dist/)")
            exit_code = 1
            continue
        text = bundle.read_text(encoding="utf-8")
        if f"'{binary_version}'" not in text and f'"{binary_version}"' not in text:
            fail(
                f"{bundle.relative_to(ROOT)}: does not embed COLDSTEP_BINARY_VERSION="
                f"{binary_version} — stale bundle; run `npm run build` and commit dist/"
            )
            exit_code = 1

    pin_text = PIN_SCRIPT.read_text(encoding="utf-8")
    pm = MARKETPLACE_TAG_RE.search(pin_text)
    if not pm:
        fail(f"{PIN_SCRIPT.relative_to(ROOT)}: MARKETPLACE_COLDSTEP_TAG declaration not found")
        return 1
    marketplace_tag = pm.group(1)
    if marketplace_tag != binary_version:
        fail(
            f"MARKETPLACE_COLDSTEP_TAG={marketplace_tag} != COLDSTEP_BINARY_VERSION="
            f"{binary_version} — bump BOTH in the same release PR (RELEASE_PROCESS.md)"
        )
        exit_code = 1

    if args.tag and args.tag != binary_version:
        fail(
            f"tag {args.tag} points at a commit whose COLDSTEP_BINARY_VERSION is "
            f"{binary_version} — this tag would ship the WRONG agent (v0.5.2 incident). "
            f"Re-point the tag at the commit that bumps src/shared.ts + dist/ to {args.tag}."
        )
        exit_code = 1

    if exit_code == 0:
        suffix = f", tag={args.tag}" if args.tag else ""
        print(f"OK COLDSTEP_BINARY_VERSION={binary_version} (src == dist == marketplace pin{suffix})")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
