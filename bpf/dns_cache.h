#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * dns_cache map: IPv4 -> FQDN (value char[256]).
 * Populated by userspace agent after parsing DNS responses.
 * Queried by BPF observability/enforcement programs for late-binding attribution.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __be32);
	__type(value, char[256]);
} dns_cache SEC(".maps");

/*
 * allowed_domains map: FQDN (64 bytes) -> __u8.
 * Populated by userspace agent based on policy.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, char[256]);
	__type(value, __u8);
} allowed_domains SEC(".maps");

#endif /* DNS_CACHE_H */
