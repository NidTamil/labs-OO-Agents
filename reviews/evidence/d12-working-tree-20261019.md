# D-12 working tree hygiene

On 2026-10-19, `git status --short --untracked-files=normal` listed 30 untracked root `.pytest-*` directories. The v1 register's count of 31 included the separate untracked `reviews/` directory; the watcher corrected this in `reviews/readiness-defects_2026-10-19_v2.md`.

The root-anchored `/.pytest-*/` rule in `.gitignore` excludes these generated test directories. They remain on disk for inspection. The six watcher-authored Markdown notes in `reviews/` are now tracked, so the ledger's evidence reference remains available after push. The intentional scored abort regression was committed with D-02, before this hygiene change.

Verification: `git check-ignore -v .pytest-scored-admission-full/` selects the new rule. `git status --porcelain --untracked-files=normal` is empty after the D-12 commit.
