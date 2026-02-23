# Security

## Threat Model Summary

- Trust boundary: backend control-plane to worker agent API.
- Primary risks: unauthorized API calls, replay attacks, container breakout, overbroad network access, secrets leakage in logs.
- Assumptions: worker host is hardened, Docker daemon is local, backend secret distribution is secure.

## Controls Implemented

- HMAC request authentication with timestamp + nonce replay protection.
- Optional bearer auth for transition compatibility.
- Input validation for instance IDs, image allowlists, and request schema.
- Idempotent operations to handle backend retries safely.
- Dedicated Docker network/container namespacing per instance.
- Structured JSON logs with request IDs.
- Prometheus metrics and health/readiness endpoints.
- Rate limiting (global + per-IP).

## Hardening Checklist

- Restrict firewall:
  - allow UDP 51820 from VPN clients.
  - allow TCP 9000 only from backend IP.
  - allow SSH only from admin IP.
- Run agent as non-root service account; add only `docker` group access.
- Keep `LAB_AGENT_HMAC_SECRET` in a secret manager, not in git.
- Enable mTLS where possible (`LAB_AGENT_TLS_*`).
- Keep Docker and kernel updated; apply security patches.
- Monitor `/metrics` and alert on auth failures and reconcile drift.
- Rotate shared secrets periodically.
