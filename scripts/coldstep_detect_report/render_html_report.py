"""Render the Tier-2 self-contained HTML artifact from report-model.json.

Designer seam: the visual / interaction surface lives in templates/report.html,
loaded with `{{ }}` placeholders. This module only does:
  - read template + CSS
  - JSON-encode the model with `</script>`-safe escaping
  - substitute placeholders
  - write the result to disk
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

# Snyk Code (python/PT, CWE-23) treats every os.environ.get(...) value as
# untrusted, so the entry-point main() canonicalises every env-var path
# through this helper before it reaches a Path()/open() sink. Inlined per
# file because Snyk's taint analysis only recognises sanitisers that live
# in the same module as the sink.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./\\:-]+$")


def _safe_workspace_path(raw: str, *, var_name: str = "path") -> str:
    if not _SAFE_PATH_RE.match(raw):
        raise ValueError(f"{var_name} contains disallowed characters")
    roots: list[str] = []
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if workspace:
        roots.append(os.path.realpath(workspace))
    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        roots.append(os.path.realpath(runner_temp))
    roots.append(os.path.realpath(tempfile.gettempdir()))
    if not workspace:
        roots.append(os.path.realpath(os.getcwd()))
    resolved = os.path.realpath(raw)
    for root in roots:
        if os.path.commonpath([resolved, root]) == root:
            return resolved
    raise ValueError(f"{var_name} resolves outside trusted roots: {resolved!r}")


def _safe_json(obj) -> str:
    """JSON encode, then defang any literal `</` so it can't break the host script tag.

    `<script type="application/json">` is parsed as raw text and only terminates on
    `</script>`. Replacing every `</` with `<\\/` keeps the byte sequence harmless
    while remaining valid JSON (the slash is an optional escape per RFC 8259).
    Insertion order of the model dict is part of the schema contract, so we keep
    `sort_keys=False` to mirror `build_report_model.build()`.
    """
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=False)
    return raw.replace("</", "<\\/")


def write_html(model: dict, html_out: str) -> None:
    template = (TEMPLATE_DIR / "report.html").read_text(encoding="utf-8")
    styles = (TEMPLATE_DIR / "styles.css").read_text(encoding="utf-8")
    payload = _safe_json(model)
    # Three-pass placeholder substitution. Order matters: STYLES is substituted
    # before MODEL_JSON so a CSS file containing the literal "{{ MODEL_JSON }}"
    # cannot inject into the JSON island. MODEL_JSON is substituted before
    # GENERATED_AT for the same reason. Today's templates and JSON contract
    # don't produce these literals, but the comment pins the invariant.
    html = (
        template
        .replace("{{ STYLES }}", styles)
        .replace("{{ MODEL_JSON }}", payload)
        .replace("{{ GENERATED_AT }}", str(model.get("generated_at", "")))
    )
    Path(html_out).write_text(html, encoding="utf-8")


def main() -> int:
    raw_model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    raw_out_path = os.environ.get("COLDSTEP_REPORT_HTML_OUT", "")
    if not raw_model_path or not raw_out_path:
        missing = [
            name for name, val in
            (("COLDSTEP_REPORT_MODEL_IN", raw_model_path), ("COLDSTEP_REPORT_HTML_OUT", raw_out_path))
            if not val
        ]
        print(f"render_html_report: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    try:
        model_path = _safe_workspace_path(raw_model_path, var_name="COLDSTEP_REPORT_MODEL_IN")
        out_path = _safe_workspace_path(raw_out_path, var_name="COLDSTEP_REPORT_HTML_OUT")
    except ValueError as e:
        print(f"render_html_report: refusing untrusted path: {e}", file=sys.stderr)
        return 1
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    write_html(model=model, html_out=out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
