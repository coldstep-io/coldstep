# Enforce mode: ignored IPv4 CIDRs (BPF LPM trie)

**Repository state (2026-04-12):** The **`ignored_ipv4_lpm`** map and **`BuildPolicyEx`** merge rules described here are **implemented on `main`**. This file remains the **BPF↔Go alignment** reference.

This note documents how **`ignored_ipv4_lpm`** in [`bpf/trace_enforce.bpf.c`](../../../bpf/trace_enforce.bpf.c) lines up with userspace policy so **enforce** does not deny traffic to merged “ignored” prefixes.

## Map

- **Type:** `BPF_MAP_TYPE_LPM_TRIE`
- **`max_entries`:** `128` (must stay aligned with **`policy.MaxIgnoredIPv4Nets`** in Go and the **≤128** merge limit in **`BuildPolicyEx`**.)
- **`BPF_F_NO_PREALLOC`:** set (same pattern as typical LPM examples).

## Key layout (`struct ns_lpm4_key`, packed, 8 bytes)

| Offset | Field        | Meaning |
|--------|--------------|---------|
| 0–3    | `prefixlen`  | Prefix length in **bits** for this trie entry (`/8` → `8`). Stored from userspace with **little-endian** `uint32` in [`internal/agent/agent_linux.go`](../../../internal/agent/agent_linux.go) (`loadIgnoredLPMMap`). |
| 4–7    | `addr`       | IPv4 **network** address in **big-endian** (first byte of IP is the MSB of the `uint32` on the wire). |

## Insertion (userspace)

For each merged `*net.IPNet` after `Mask.Size()` yields IPv4 `/n`:

1. `ones` = prefix length (0–32).
2. `network` = `ip.To4().Mask(n.Mask)`.
3. Write `prefixlen` = `ones` into bytes 0–3 (LE).
4. Write `network` into bytes 4–7 (BE).

## Lookup (BPF)

Before allowlist membership, **`dst_in_ignored`** builds a key with **`prefixlen = 32`** and **`addr = ctx->user_ip4`** (destination IPv4 in **network byte order** as `__be32`), then `bpf_map_lookup_elem`. The trie returns a hit if any inserted prefix covers that address.

## Hooks

Both **`cgroup/connect4`** and **`cgroup/sendmsg4`** call **`dst_in_ignored`** after **`enforcement_enabled()`** and before **`dst_is_allowlisted`**. A hit **returns `1`** (allow syscall) without emitting a deny.

## Failure modes

- **`loadIgnoredLPMMap`** returns an error if the map handle is **nil** while there are nets to load, or if **`len(nets) > policy.MaxIgnoredIPv4Nets`** (should not happen if **`BuildPolicyEx`** succeeded).
- If userspace and BPF caps ever diverge, policy classification and enforcement could disagree—keep **`MaxIgnoredIPv4Nets`** and **`max_entries`** in sync.
