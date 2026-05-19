/*
 * IPv6 LPM trie key for defend allowlist map (P2-1, Phase 2).
 * Layout matches BPF_MAP_TYPE_LPM_TRIE: prefixlen (CPU-endian) + addr (network order).
 *
 * Userspace must mirror this wire format byte-for-byte in
 * loadAllowedLPMv6Map: 20-byte buffer where bytes [0:4] are the prefix
 * length in CPU/little-endian order and bytes [4:20] are the IPv6 address
 * in network byte order. Drift between the two sides equals silent BPF
 * EINVAL on Update at agent start, surfacing as IPv6 defend-bypass.
 */
#ifndef COLDSTEP_DEFEND_LPM_V6_KEY_H
#define COLDSTEP_DEFEND_LPM_V6_KEY_H

struct lpm_v6_key {
	__u32 prefixlen;
	__u8 addr[16];
} __attribute__((packed));

#endif /* COLDSTEP_DEFEND_LPM_V6_KEY_H */
