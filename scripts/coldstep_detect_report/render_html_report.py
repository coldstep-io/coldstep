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
import sys
from pathlib import Path

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


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
    model_path = os.environ.get("COLDSTEP_REPORT_MODEL_IN", "")
    out_path = os.environ.get("COLDSTEP_REPORT_HTML_OUT", "")
    if not model_path or not out_path:
        missing = [
            name for name, val in
            (("COLDSTEP_REPORT_MODEL_IN", model_path), ("COLDSTEP_REPORT_HTML_OUT", out_path))
            if not val
        ]
        print(f"render_html_report: missing required env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    write_html(model=model, html_out=out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
