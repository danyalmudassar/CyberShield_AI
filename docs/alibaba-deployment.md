# Alibaba Cloud deployment

## Deployment status

The application is packaged for a single Linux ECS server. No Alibaba resource has
been provisioned, charged or deployed by this setup. Actual deployment requires an
eligible ECS instance, public IP, SSH access and a DNS hostname pointing to it.
An account or a Model Studio/Bailian model allowance is not by itself an ECS server.
Confirm the account's actual offer and bandwidth/disk/expiry charges in the console.

## Architecture

Internet → Caddy HTTPS gateway → Next.js dashboard → FastAPI worker and SQLite.
Scan/auth databases, PDF reports and TLS certificate state use persistent Docker
volumes. Backend and frontend do not publish host ports. Only gateway ports 80/443
are public. Cookies use Secure/HttpOnly/SameSite and the exact configured origin.
The first deployment runs the full application in fixture-only demo mode.

For this configured memory budget, a Linux x86_64 instance with 2 vCPU, 4 GiB RAM
and sufficient disk space for Docker images is a practical starting point; this is
an engineering recommendation, not a promise that the free trial includes it.
Use an eligible region offered in your account. Confirm all pricing before creating
an instance, public IP, disk, snapshot or other resource. Free-trial expiry can incur
charges; configure the account's billing alerts and expiry handling.

## Server preparation

1. Create or use an approved ECS instance with Ubuntu 24.04 LTS and a public IP.
2. Configure a security group: inbound TCP 80 and 443 for the website; restrict
   SSH/22 to your administrator IP. Do not expose 3000, 8000 or database ports.
3. Point your domain's A record to the server. Only set AAAA if IPv6 actually works.
4. Install Docker Engine and the Compose plugin using the official Ubuntu guide
   below. Use SSH keys; do not paste private keys or root credentials into chat.

## Start the complete stack

On the server, clone the release branch until it has been merged into master:

```bash
git clone --branch master https://github.com/danyalmudassar/CyberShield_AI.git CyberShield
cd CyberShield
python3 deploy/cloud/configure.py --domain security.example.com
docker compose --env-file .cloud.env -p cybershield-cloud -f compose.cloud.yaml config -q
docker compose --env-file .cloud.env -p cybershield-cloud -f compose.cloud.yaml up -d --build --wait
```

Replace `security.example.com` with your own configured hostname. The script
privately prompts for the operator password and refuses to overwrite existing
credentials. It does not contact Alibaba or create resources. Caddy obtains and
renews a certificate when public DNS and inbound ports are correct. Open your
HTTPS `/login` page and sign in as `operator@cybershield.ai`.

## Verify before sharing the URL

```bash
docker compose --env-file .cloud.env -p cybershield-cloud -f compose.cloud.yaml ps
curl --fail https://security.example.com/api/ready
curl -I https://security.example.com/login
```

Then verify: wrong password rejected, configured login succeeds, demo assessment
completes, PDF downloads, reopening a saved scan works, and logout blocks access.
Restart the stack and confirm saved history/PDFs remain. Never run `down -v` on the
persistent deployment: it deletes its volumes. Normal `restart` and `up -d` retain them.

## Real target assessments (optional)

After reviewing target authorization and hosting-provider policy, add the explicit
live override. This attaches an outbound network and allows live/rules-only jobs:

```bash
docker compose --env-file .cloud.env -p cybershield-cloud -f compose.cloud.yaml -f compose.cloud-live.yaml up -d --build --wait
```

Rules-only performs network probes without an AI key. AI analysis also requires a
supported provider's credentials/configuration; a cloud hosting account alone does
not configure a model provider. Keep keys in server-managed secrets, never Git.
To return to demo-only, run the original single-file `up` command again.

## Persistence is not a backup

A retained Docker volume survives container recreation, not loss of the ECS disk.
Follow [the existing backup and restore runbook](backup-restore.md), adapting its
Compose filename/project to `compose.cloud.yaml` / `cybershield-cloud`. Store an
encrypted copy off the instance. Off-host backups and monitoring require separate
operator configuration; they are not claimed complete by this template.

## Official references

- [Alibaba free-trial eligibility](https://www.alibabacloud.com/help/en/user-center/product-overview/learn-about-free-trials)
- [ECS security groups](https://www.alibabacloud.com/help/en/ecs/user-guide/start-using-security-groups)
- [Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Caddy automatic HTTPS requirements](https://caddyserver.com/docs/automatic-https)

## Local deployment verification — 7 September 2026

The three-container stack was built and tested behind a local HTTPS gateway with
an internal test certificate. Login, demo scan, valid PDF download and logout
passed. After backend/frontend restart, the same saved scan and identical PDF
SHA-256 were retrieved. Cookies were Secure and HttpOnly. The default backend
network is internal and only the gateway publishes host ports.

The gateway removes the image binary's file capability because it listens on
unprivileged internal ports; `cap_drop: ALL` is retained. Its local readiness
listener is not exposed on a host port. This is local infrastructure verification,
not evidence of an Alibaba instance or public certificate being provisioned.
