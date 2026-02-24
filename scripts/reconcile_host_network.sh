#!/usr/bin/env bash
set -euo pipefail

# Prune stale host networking artifacts for lab-agent managed instances:
# - stale iptables rules referencing removed docker bridges
# - stale lab-agent managed docker networks with no endpoints

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "error: run as root (sudo)" >&2
  exit 1
fi

APPLY=1
if [[ "${1:-}" == "--dry-run" ]]; then
  APPLY=0
fi

log() { printf '%s\n' "$*" >&2; }
run() {
  if [[ "$APPLY" -eq 1 ]]; then
    "$@"
  else
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
  fi
}

bridge_exists() {
  local ifname="$1"
  ip link show "$ifname" >/dev/null 2>&1
}

extract_bridge_refs() {
  local line="$1"
  grep -oE 'br-[[:alnum:]]+' <<<"$line" | sort -u || true
}

delete_rule_line() {
  local table="$1"
  local line="$2"
  local body="${line#-A }"
  read -r -a parts <<<"$body"
  if [[ "$table" == "filter" ]]; then
    run iptables -D "${parts[@]}"
  else
    run iptables -t "$table" -D "${parts[@]}"
  fi
}

prune_stale_bridge_rules() {
  local table="$1"
  local chain="$2"
  local removed=0
  local rules
  rules="$(iptables -t "$table" -S "$chain" 2>/dev/null || true)"
  if [[ -z "$rules" ]]; then
    echo 0
    return 0
  fi
  while IFS= read -r line; do
    [[ "$line" == -A* ]] || continue
    local stale=0
    while IFS= read -r br; do
      [[ -n "$br" ]] || continue
      if ! bridge_exists "$br"; then
        stale=1
      fi
    done < <(extract_bridge_refs "$line")
    if [[ "$stale" -eq 1 ]]; then
      log "prune stale rule ($table/$chain): $line"
      delete_rule_line "$table" "$line"
      removed=$((removed + 1))
    fi
  done <<<"$rules"
  echo "$removed"
}

prune_stale_networks() {
  local removed=0
  while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    local nid="${row%% *}"
    local nname="${row#* }"
    local endpoint_count
    endpoint_count="$(docker network inspect "$nid" --format '{{len .Containers}}' 2>/dev/null || echo 0)"
    if [[ "$endpoint_count" == "0" ]]; then
      log "prune stale managed network: $nname ($nid)"
      run docker network rm "$nid" >/dev/null
      removed=$((removed + 1))
    fi
  done < <(docker network ls --filter label=lab_agent.managed=true --format '{{.ID}} {{.Name}}')
  echo "$removed"
}

log "reconcile_host_network: start (apply=$APPLY)"
fwd_removed="$(prune_stale_bridge_rules filter FORWARD)"
du_removed="$(prune_stale_bridge_rules filter DOCKER-USER)"
raw_removed="$(prune_stale_bridge_rules raw PREROUTING)"
net_removed="$(prune_stale_networks)"
log "reconcile_host_network: done forward_removed=$fwd_removed docker_user_removed=$du_removed raw_removed=$raw_removed networks_removed=$net_removed"
