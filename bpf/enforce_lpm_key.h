/*
 * IPv4 LPM trie key for enforce allowlist + ignored-CIDR maps (cgroup + LSM).
 * Layout matches BPF_MAP_TYPE_LPM_TRIE: prefixlen (CPU-endian) + addr (network order).
 */
#ifndef COLDSTEP_ENFORCE_LPM_KEY_H
#define COLDSTEP_ENFORCE_LPM_KEY_H

struct ns_lpm4_key {
	__u32 prefixlen;
	__be32 addr;
} __attribute__((packed));

#endif /* COLDSTEP_ENFORCE_LPM_KEY_H */
