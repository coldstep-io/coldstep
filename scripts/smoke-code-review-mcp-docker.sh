#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-coldstep-code-review-mcp:smoke}"

docker build -t "${IMAGE_TAG}" "${ROOT}/docker/code-review-assistant"

# Override ENTRYPOINT so we run assertions instead of starting stdio MCP.
docker run --rm --entrypoint python "${IMAGE_TAG}" -c "
import sys
sys.path.insert(0, '/app')
import server
text = server._load_expert_prompt()
assert len(text) > 200, 'prompt too short'
assert 'BPF' in text or 'bpf' in text, 'expected BPF mention in rubric'
cl = server._checklist_for('go', '')
assert 'race' in cl.lower() or 'error' in cl.lower()
print('smoke_ok')
"

echo "smoke-code-review-mcp-docker: passed"
