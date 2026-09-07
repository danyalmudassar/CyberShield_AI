# Hosted release verification

The public target is `danyalmudassar/CyberShield_AI`. The isolated release branch
`release/2026-09-07-verified-local` combines the project as `backend/` and
`frontend/`, with Compose, launcher, root docs and root GitHub Actions workflows.
The existing remote default branch was not merged or rewritten. Original local
backend/frontend repositories and their uncommitted development state were preserved.

Root workflows adapt checkout/cache paths and command working directories for the
combined layout. Nested `.github/` files remain the independent repository templates;
GitHub runs only the root workflows in the combined release. Runtime databases,
PDFs, local secrets, virtual environments and node_modules were excluded from the
snapshot. Candidate filenames and common credential patterns were checked; this is
not a comprehensive third-party secret-scanning/security certification.

Release source commit: `5b235bc4ec9d69194016d6771676ed4e339ed5d7`.

- [Backend workflow](https://github.com/danyalmudassar/CyberShield_AI/actions/runs/34111998117)
- [Frontend workflow](https://github.com/danyalmudassar/CyberShield_AI/actions/runs/34111998121)
- [Release branch](https://github.com/danyalmudassar/CyberShield_AI/tree/release/2026-09-07-verified-local)

The first hosted backend attempt rejected a YAML scalar containing
`--only-binary=:all:`. The install command now uses a block scalar in both the root
workflow and independent-backend template. The first run is retained as failed
history; it is not evidence for the corrected commit.

Exact snapshot verification also ran locally after relocation: 346 backend tests
passed, one integration test was deselected and two dependency deprecation warnings
remained. Clean frontend npm installation, TypeScript check and production build
passed. Hosted job results must be interpreted for the commit linked above.

For subsequent combined-repository development, use the release checkout/branch:
`/tmp/cybershield-hosted-release` was the isolated publishing checkout in this
session. The original nested local repositories do not automatically become a
single Git repository. Review and merge the release branch deliberately; no PR
message, default-branch merge or production deployment was performed here.

## Final hosted results

Both workflows completed successfully for `5b235bc4ec9d69194016d6771676ed4e339ed5d7`.
Backend: hashed install, `pip check`, **346 passed / 1 deselected / 2 warnings**
in 55.74s, runtime container build and non-root offline import check. Frontend:
locked install, TypeScript, production build and standalone container build all
passed. Required branch protection checks, merge and deployment remain separate
actions. These final evidence notes are recorded in the original workspace; they
do not change the exact code commit tested on GitHub.
