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
- `LAB_AGENT_LAB_CIDRS=172.16.0.0/12`
- `LAB_AGENT_STARTUP_FIREWALL_CHECK=true`
- `LAB_AGENT_MANAGE_DOCKER_USER_RULES=false`
- `LAB_AGENT_REGISTRY_SERVER_ADDRESS=ghcr.io`

### Startup firewall self-check

On startup, the agent checks `iptables -t raw -S PREROUTING` and fails fast if a `DROP` rule targets configured lab CIDRs (`LAB_AGENT_LAB_CIDRS`).

This prevents silent VPN->lab breakage caused by raw-table drops before FORWARD/NAT.

Disable only for controlled debugging:

```bash
LAB_AGENT_STARTUP_FIREWALL_CHECK=false
```

### Managed DOCKER-USER rules

When enabled, the agent will manage VPN-to-lab forwarding rules automatically:
- startup: insert accept rules in `filter/DOCKER-USER`.
- shutdown: remove those managed rules.

Enable with:

```bash
LAB_AGENT_MANAGE_DOCKER_USER_RULES=true
```

Rules managed:
- `-i <wg_interface> -d <lab_cidr> -j ACCEPT` for each lab CIDR.
- `-o <wg_interface> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`.

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

## Host Cleanup/Reconcile Script

Use `scripts/reconcile_host_network.sh` to prune stale per-instance host artifacts:
- stale iptables rules referencing deleted `br-*` interfaces in `FORWARD`, `DOCKER-USER`, and `raw/PREROUTING`.
- stale Docker networks with label `lab_agent.managed=true` and zero endpoints.

Preview:

```bash
sudo ./scripts/reconcile_host_network.sh --dry-run
```

Apply:

```bash
sudo ./scripts/reconcile_host_network.sh
```

Or via Makefile:

```bash
make host-reconcile
```

## Security Notes

- Restrict API at firewall to backend IP only.
- Never log secrets; agent logs are structured JSON with request IDs.
- Use image allowlist prefixes.
- Prefer mTLS in production (`LAB_AGENT_TLS_*`).
- See `docs/security.md` for threat model and checklist.
