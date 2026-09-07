# CyberShield workspace redesign — 7 September 2026

## Delivered experience

- Dedicated `/login` page with visible labels, password visibility control, loading and error states. Existing HttpOnly cookie authentication and CSRF header retained.
- Anonymous dashboard visits redirect to login; successful login opens the workspace. Logout revokes the server session before leaving the workspace.
- Navy navigation, teal action color, semantic light/dark surfaces, consistent spacing and responsive layouts.
- Saved assessment count and selected assessment status use actual API data. No fabricated live counters. Demo findings are excluded from the confirmed finding count.
- Demo is the default form mode. Rules-only and live remain explicit choices; backend deployment policy still controls which scans are accepted.
- Stage outcome cards preserve completed, failed, partial, skipped and fixture distinctions. Expandable activity log.
- Filterable existing findings and control evidence remain available. Recent assessments reopen persisted scan results.
- Document-style executive summary and authenticated PDF download. Historical benchmark records are collapsed and clearly labeled as historical.
- External font dependency removed; system typography works offline.

## Verification

Production Next.js build and TypeScript passed. Real Chromium testing against an isolated FastAPI demo backend verified anonymous redirect, invalid credentials, successful configured login, demo scan completion, report PDF bytes, all result navigation sections and logout revocation. No page JavaScript errors were observed.

Checked document overflow at 320, 768, 1024 and 1440 pixels. Captured desktop/mobile login, desktop/mobile dashboard, dark theme, completed assessment and report screenshots in `ui-preview/`. These are fixture demonstration screenshots, not a live security audit.

Preview used `http://127.0.0.1:3100` with a separate temporary database; it does not migrate or replace the user's saved assessments. Use the regular launcher for the regular workspace database.

## Scope

The final release also adds `/signup` with persistent operator accounts. Email verification and password reset delivery remain unconfigured; cloud packaging does not itself provision a server. This is a verified local demo release, not a claim of complete production security or full automated compliance certification.

Final signup browser verification passed: password confirmation, operator-only role,
admin endpoint denial, reload, logout and subsequent login. Signup layouts were
checked at 320, 768 and 1440 pixels. Backend verification: 366 passed, one
integration test deselected, two dependency deprecation warnings. Cloud setup
helper: four unit tests passed. Production frontend/container build passed.
