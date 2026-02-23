#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import secrets
import time


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign(secret: str, method: str, path: str, timestamp: str, nonce: str, body_bytes: bytes) -> str:
    body_hash = sha256_hex(body_bytes)
    canonical = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate lab-agent HMAC headers")
    parser.add_argument("--secret", required=True, help="Shared HMAC secret")
    parser.add_argument("--method", required=True, help="HTTP method, e.g. POST")
    parser.add_argument("--path", required=True, help="Request path, e.g. /v1/instances")
    parser.add_argument("--body", default="", help="Raw JSON/body string")
    parser.add_argument("--timestamp", default="", help="Unix seconds; defaults to now")
    parser.add_argument("--nonce", default="", help="Nonce; defaults to random")
    args = parser.parse_args()

    method = args.method.upper()
    timestamp = args.timestamp or str(int(time.time()))
    nonce = args.nonce or secrets.token_hex(16)
    body_bytes = args.body.encode()

    signature = sign(args.secret, method, args.path, timestamp, nonce, body_bytes)

    out = {
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
        "body_sha256": sha256_hex(body_bytes),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
