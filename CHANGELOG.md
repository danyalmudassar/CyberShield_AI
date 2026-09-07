# Changelog

## 2026-09-07 — Submission release

### Added
- Combined backend/frontend repository with locked dependency checks and container builds.
- Dedicated login and signup pages with persistent operator accounts, hashed passwords,
  HttpOnly sessions, request-origin checks and registration/login rate limits.
- Responsive security workspace, light/dark themes, assessment outcomes and document-style reports.
- Persistent scan jobs, replayable progress, ownership checks and PDF storage.
- Backup/restore tooling and worker/database readiness reporting.
- Single-server Alibaba ECS deployment package with Caddy HTTPS and persistent volumes.

### Corrected
- Live/deterministic/fixture evidence separation and conservative scoring.
- Report path containment, target transport boundaries and process termination.
- Lab login verification and incomplete directory-probe outcomes.

### Release boundary
- Local demo and automated verification are the established submission path.
- Alibaba infrastructure, public DNS/certificates and off-host backups require
  operator configuration. A packaged deployment is not a completed cloud deployment.
- Email ownership verification and self-service password recovery are not configured.
- The technical control matrix is project-defined, not a compliance certification.
