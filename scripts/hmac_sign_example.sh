#!/usr/bin/env bash
set -euo pipefail

# Example helper for the exact HMAC contract used by lab-agent.
# Signature = HMAC_SHA256(secret, method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + body_sha256_hex)

SECRET=${LAB_AGENT_HMAC_SECRET:-change-me}
METHOD=${1:-POST}
PATH_ONLY=${2:-/v1/instances}
BODY=${3:-"{}"}

TIMESTAMP=$(date +%s)
NONCE=$(openssl rand -hex 16)
BODY_SHA=$(printf '%s' "$BODY" | sha256sum | awk '{print $1}')
CANONICAL="${METHOD}\n${PATH_ONLY}\n${TIMESTAMP}\n${NONCE}\n${BODY_SHA}"
SIGNATURE=$(printf '%b' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

echo "X-Agent-Timestamp: ${TIMESTAMP}"
echo "X-Agent-Nonce: ${NONCE}"
echo "X-Agent-Signature: ${SIGNATURE}"
