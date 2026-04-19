"""elon Orchestrator — public surface (Sprint 1).

Twelve functions, no more. See docs/superpowers/specs/2026-04-19-elon-umbrella-design.md
section 5.6 risk #2: keeping the public surface small is a hard constraint.
"""

from scripts.elon_orchestrator.frontmatter import read as read_frontmatter
from scripts.elon_orchestrator.frontmatter import write as write_with_frontmatter
from scripts.elon_orchestrator.index import append_index_row
from scripts.elon_orchestrator.persona import load_persona_dial
from scripts.elon_orchestrator.query import (
    find_by_tag,
    find_by_wikilink_target,
    find_records_for_wiki,
)
from scripts.elon_orchestrator.tags import load_tag_allowlist, validate_tag
from scripts.elon_orchestrator.vault_cli import vault_cli
from scripts.elon_orchestrator.wikilink import (
    closest_wikilink_match,
    resolve as resolve_wikilink,
)

__all__ = [
    "append_index_row",
    "closest_wikilink_match",
    "find_by_tag",
    "find_by_wikilink_target",
    "find_records_for_wiki",
    "load_persona_dial",
    "load_tag_allowlist",
    "read_frontmatter",
    "resolve_wikilink",
    "validate_tag",
    "vault_cli",
    "write_with_frontmatter",
]
