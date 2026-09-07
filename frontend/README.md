# CyberShield frontend

Next.js dashboard for authentication, assessment configuration, progress, findings and saved reports. The FastAPI service lives in [../backend](../backend/).

## Local development

Use the [root setup instructions](../README.md) and `python run_local.py` to launch both services with matching local URLs and authentication settings.

For frontend-only development, run `npm ci` and `npm run dev` here. Configure `CYBERSHIELD_API_URL` to the backend origin; server-side route handlers proxy API traffic. Do not expose provider keys through `NEXT_PUBLIC_*` variables.

## Layout

- `app/`: routes, components, hooks and backend proxy handlers.
- `lib/`: shared API types and server utilities.
- `public/`: static assets.
- `tests/`: browser verification scripts.
- `Dockerfile`: standalone production image.

## Verification and deployment

`npm run build` compiles the application and checks TypeScript. The root GitHub workflow also verifies the production container. Railway uses root directory `/frontend`, this directory's Dockerfile and `/api/ready` for readiness.
