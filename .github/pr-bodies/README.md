# PR description bodies (UTF-8)

Use **tracked `.md` files here** for GitHub PR descriptions so text is not corrupted by shell quoting (especially **PowerShell** passing `--body "..."` to `gh`, which can mangle backticks and Unicode).

## Rules

1. Save files as **UTF-8** (no accidental Latin-1 / Windows code pages).
2. Prefer **ASCII** for bullets; avoid curly quotes unless you verify the file bytes.
3. Apply to GitHub with **`gh` body-file**, never inline `--body` for long text on Windows:

```bash
gh pr create --draft --base main --head dev --title "..." --body-file .github/pr-bodies/my-pr.md
gh pr edit 88 --body-file .github/pr-bodies/my-pr.md
```

CI **`scripts/check-encoding.sh`** rejects **U+FFFD** replacement bytes (**`EF BF BD`**) and known mojibake in tracked sources including these files.
