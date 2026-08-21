#!/usr/bin/env bash

set -euo pipefail

# Prints the accepted action names for this helper.
# Called by the command dispatcher when no known action is supplied.
usage() {
  printf '%s\n' "usage: bash firewall-setup/firewall-setup.sh {setup|show|cleanup}"
}

# Verifies that the router namespace required by every action exists.
# Called by setup_firewall, show_firewall, and cleanup_firewall.
require_topology() {
  if ! sudo ip netns exec mesh-r true 2>/dev/null; then
    printf '%s\n' "mesh-r does not exist; run: bash namespaces.md" >&2
    exit 1
  fi
}

# Installs the temporary return route and stateful nftables forwarding policy.
# Called by the command dispatcher for the setup action.
setup_firewall() {
  require_topology

  # Give mesh-b a path toward mesh-a so an unsolicited packet reaches the
  # router. The firewall, rather than a missing route, can then reject it.
  sudo ip -n mesh-b route replace 10.10.0.0/24 via 192.0.2.10 dev b0

  if sudo ip netns exec mesh-r nft list table inet meshlet_filter >/dev/null 2>&1; then
    sudo ip netns exec mesh-r nft delete table inet meshlet_filter
  fi

  sudo ip netns exec mesh-r nft add table inet meshlet_filter
  sudo ip netns exec mesh-r nft \
    'add chain inet meshlet_filter forward { type filter hook forward priority filter; policy drop; }'

  # New outbound traffic is permitted. Later packets belonging to that same
  # tracked exchange are also permitted.
  sudo ip netns exec mesh-r nft \
    'add rule inet meshlet_filter forward iifname "r0" oifname "r1" ct state new,established,related counter accept'

  # Public-to-private traffic is permitted only when connection tracking says
  # it belongs to an exchange that already exists.
  sudo ip netns exec mesh-r nft \
    'add rule inet meshlet_filter forward iifname "r1" oifname "r0" ct state established,related counter accept'

  # This explicit final rule gives rejected packets a visible counter.
  sudo ip netns exec mesh-r nft \
    'add rule inet meshlet_filter forward counter drop'

  printf '%s\n' "live firewall installed"
  show_firewall
}

# Prints the router's live forwarding rules and packet counters.
# Called after setup and by the command dispatcher for the show action.
show_firewall() {
  require_topology
  sudo ip netns exec mesh-r nft list chain inet meshlet_filter forward
}

# Removes the temporary nftables table and mesh-b return route.
# Called by the command dispatcher for the cleanup action.
cleanup_firewall() {
  require_topology

  if sudo ip netns exec mesh-r nft list table inet meshlet_filter >/dev/null 2>&1; then
    sudo ip netns exec mesh-r nft delete table inet meshlet_filter
  fi

  sudo ip -n mesh-b route del 10.10.0.0/24 via 192.0.2.10 dev b0 2>/dev/null || true
  printf '%s\n' "live firewall and temporary mesh-b route removed"
}

case "${1:-}" in
  setup)
    setup_firewall
    ;;
  show)
    show_firewall
    ;;
  cleanup)
    cleanup_firewall
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
