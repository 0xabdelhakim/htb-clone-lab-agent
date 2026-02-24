# htb-clone-lab-agent

Secure, observable, idempotent lab orchestration service for HTB Clone worker droplets.

## Canonical API

Canonical routes:
- `GET /healthz`
- `GET /readyz`
- `GET /v1/instances`
- `GET /v1/instances/{id}`
- `POST /v1/instances`
- `POST /v1/instances/{id}/start`
- `POST /v1/instances/{id}/stop`
- `DELETE /v1/instances/{id}`
- `POST /v1/reconcile`
- `GET /metrics`

Backward compatibility aliases are also served under `/api/v1/*`.

## Authentication (Exact HMAC Contract)

Default auth mode is `hmac`.

Headers:
- `X-Agent-Timestamp` (Unix seconds)
- `X-Agent-Nonce` (random string)
- `X-Agent-Signature` (lowercase hex)

Canonical string:

```text
METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + SHA256_HEX(raw_body_bytes)
```

Signature:

```text
HMAC_SHA256(secret, canonical_string)
```

Replay protection:
- request timestamp must be within `LAB_AGENT_HMAC_SKEW_SECONDS` (default `300`).
- nonce reuse is rejected.
- nonce cache TTL defaults to `skew + 60` (`LAB_AGENT_NONCE_TTL_SECONDS=360`).

Helper:
- `scripts/sign_request.py`

Example:

```bash
python3 scripts/sign_request.py \
  --secret "$LAB_AGENT_HMAC_SECRET" \
  --method POST \
  --path /v1/instances \
  --body '{"instance_id":"...","user_id":"...","lab_id":"...","image":"ghcr.io/labs/demo:latest","ttl_seconds":7200}'
```

Bearer mode remains optional via `LAB_AGENT_AUTH_MODE=bearer`.

## Idempotency

- `POST /v1/instances` is upsert-by-`instance_id`.
- `DELETE /v1/instances/{id}` is idempotent.
- `POST /v1/instances/{id}/start` is idempotent.
- `POST /v1/instances/{id}/stop` is idempotent.

## Reconciliation

- API: `POST /v1/reconcile`
- CLI: `lab-agent reconcile`

The reconcile command uses the same logic as the API and prints drift summary JSON to stdout.

## Quick Start (Ubuntu 24.04 worker)

1. Install dependencies:

```bash
sudo apt update
sudo apt install -y docker.io wireguard-tools
sudo systemctl enable --now docker
```

2. Build binary:

```bash
make build
```

3. Configure environment:

```bash
cp .env.example /etc/lab-agent.env
sudo mkdir -p /var/lib/lab-agent
```

4. Deploy systemd unit:

```bash
sudo useradd --system --home /var/lib/lab-agent --shell /usr/sbin/nologin lab-agent || true
sudo cp bin/lab-agent /usr/local/bin/lab-agent
sudo cp deploy/systemd/lab-agent.service /etc/systemd/system/lab-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now lab-agent
```

5. Firewall rules (required):
- allow UDP `51820`.
- allow TCP `9000` **only** from backend IP.
- allow SSH **only** from admin IP.

Example with UFW:

```bash
sudo ufw default deny incoming
sudo ufw allow from <BACKEND_IP> to any port 9000 proto tcp
sudo ufw allow 51820/udp
sudo ufw allow from <ADMIN_IP> to any port 22 proto tcp
sudo ufw enable
```

## Local Development

Run with Docker Compose:

```bash
docker compose up --build
```

Run directly:

```bash
make run
```

Test:

```bash
make test
```

## Config

Load order:
1. defaults
2. optional YAML from `LAB_AGENT_CONFIG_FILE`
3. env overrides

Important defaults:
- `LAB_AGENT_LISTEN_ADDR=:9000`
- `LAB_AGENT_AUTH_MODE=hmac`
- `LAB_AGENT_HMAC_SKEW_SECONDS=300`
- `LAB_AGENT_NONCE_TTL_SECONDS=360`
- `LAB_AGENT_RATE_LIMIT_ENABLED=true`
- `LAB_AGENT_RATE_LIMIT_GLOBAL_RPS=100`
- `LAB_AGENT_RATE_LIMIT_PER_IP_RPS=20`
- `LAB_AGENT_REGISTRY_SERVER_ADDRESS=ghcr.io`

### Registry pull auth (GHCR/private images)

The orchestrator now:
- skips pull if the image is already present locally.
- uses Docker API pull auth when configured.

Set these on worker when using private GHCR images:

```bash
LAB_AGENT_REGISTRY_USERNAME=<github-username>
LAB_AGENT_REGISTRY_TOKEN=<token-with-read-packages>
LAB_AGENT_REGISTRY_SERVER_ADDRESS=ghcr.io
```

If these are empty, agent attempts anonymous pull.

## Security Notes

- Restrict API at firewall to backend IP only.
- Never log secrets; agent logs are structured JSON with request IDs.
- Use image allowlist prefixes.
- Prefer mTLS in production (`LAB_AGENT_TLS_*`).
- See `docs/security.md` for threat model and checklist.

