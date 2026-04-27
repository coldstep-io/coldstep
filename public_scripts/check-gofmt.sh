#!/usr/bin/env bash
# List tracked *.go that need gofmt (non-empty => fail). Skips paths missing from
# the working tree so local checkouts mid-rename do not trip `stat …: no such file`.
set -euo pipefail
if ! git ls-files '*.go' | grep -q .; then
	echo "no tracked Go files" >&2
	exit 1
fi
existing=()
while IFS= read -r -d '' f; do
	if [[ -f "$f" ]]; then
		existing+=("$f")
	fi
done < <(git ls-files -z -- '*.go')
if ((${#existing[@]} == 0)); then
	echo "no existing tracked Go files in working tree" >&2
	exit 1
fi
out="$(gofmt -l "${existing[@]}")"
if [[ -n "${out}" ]]; then
	if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
		echo "::error::Run gofmt on:" >&2
	else
		echo "gofmt needed on:" >&2
	fi
	echo "${out}" >&2
	exit 1
fi
