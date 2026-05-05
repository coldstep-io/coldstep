# PR description bodies (UTF-8)

Use **tracked `.md` files here** for GitHub PR descriptions so text is not corrupted by shell quoting (especially **PowerShell** passing `--body "..."` to `gh`, which can mangle backticks and Unicode). The same UTF-8 hygiene applies to **all** scanned sources in the repo (see **`scripts/check-encoding.sh`**).

## Rules

1. Save files as **UTF-8** (no accidental Latin-1 / Windows code pages).
2. Prefer **ASCII** for bullets; avoid curly quotes unless you verify the file bytes.
3. Type **BPF** and **eBPF** as plain ASCII — never commit byte sequence **EF BF BD** (**U+FFFD**, replacement character). Broken paste or PowerShell inline **`gh --body`** can turn **BPF** into garbage such as a replacement glyph followed by **`pf`**.
4. Apply to GitHub with **`gh` body-file**, never inline `--body` for long text on Windows:

```bash
gh pr create --draft --base main --head dev --title "..." --body-file .github/pr-bodies/my-pr.md
gh pr edit 88 --body-file .github/pr-bodies/my-pr.md
```

CI **`scripts/check-encoding.sh`** rejects invalid UTF-8, **U+FFFD** replacement bytes (**`EF BF BD`**), and known mojibake in tracked sources including these files; it warns when **U+FFFD** appears immediately before **`pf`** / **`BPF`** (typical mangled **BPF** token).
