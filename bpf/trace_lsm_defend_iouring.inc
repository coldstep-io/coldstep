/*
 * io_uring LSM defend section of bpf/trace_defend_all.bpf.c (H15).
 * IPv4 only (`lsm/io_uring_cmd`).
 *
 * Defense-in-depth supplement to lsm/socket_connect + lsm/socket_sendmsg:
 * io_uring's IORING_OP_URING_CMD path (e.g. socket uring cmds) can target
 * `struct file *` instances backed by sockets and reach the network stack
 * without going through `security_socket_sendmsg()`. The kernel exposes
 * security_uring_cmd() (CONFIG_BPF_LSM + lsm= chain includes bpf), and
 * IORING_OP_SEND / IORING_OP_SENDMSG submit paths route through
 * sock_sendmsg() which fires the existing lsm_socket_sendmsg hook — this
 * hook closes the URING_CMD branch specifically.
 *
 * Implementation: read `ioucmd->file`, treat `file->private_data` as
 * `struct socket *` and verify by reading `sk->__sk_common.skc_family` —
 * non-socket files have a NULL or non-AF_INET sk and are passed (returns 0).
 * For AF_INET sockets, read the connected peer (`skc_daddr`/`skc_dport`)
 * and apply the same LPM allowlist + DNS-cache + ignored-CIDR policy used
 * by lsm_socket_sendmsg. Deny → -EPERM and a `lsm_deny_events` ringbuf
 * sample identical to the other LSM hooks.
 *
 * Maps in this section reuse the `lsm_*` family from
 * `trace_lsm_defend_lsm.inc` (which must be #include'd first). Policy
 * helpers `lsm_defense_enabled` / `lsm_dst_in_ignored` /
 * `lsm_dst_is_allowlisted` / `lsm_emit_deny_event_ipv4` are also defined
 * by that include.
 *
 * The combined .bpf.c provides vmlinux/BPF helpers, LICENSE, shared
 * #defines (IPPROTO_*, AF_INET, EPERM, COLDSTEP_*) and dns_cache.h.
 */

/*
 * LSM hook: returns 0 to allow, -EPERM to deny. Only AF_INET sockets with
 * a non-zero connected peer are evaluated; everything else falls through
 * to allow so non-network uring cmds (NVMe pass-through, etc.) are not
 * accidentally affected.
 */
SEC("lsm/io_uring_cmd")
int BPF_PROG(lsm_io_uring_cmd, struct io_uring_cmd *ioucmd)
{
	if (!lsm_defense_enabled())
		return 0;

	if (!ioucmd)
		return 0;

	struct file *file = NULL;
	if (bpf_probe_read_kernel(&file, sizeof(file), &ioucmd->file))
		return 0;
	if (!file)
		return 0;

	void *priv = NULL;
	if (bpf_probe_read_kernel(&priv, sizeof(priv), &file->private_data))
		return 0;
	if (!priv)
		return 0;

	struct socket *sock = (struct socket *)priv;
	struct sock *sk = NULL;
	if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk))
		return 0;
	if (!sk)
		return 0;

	__u16 sk_family = 0;
	if (bpf_probe_read_kernel(&sk_family, sizeof(sk_family),
				  &sk->__sk_common.skc_family))
		return 0;
	if (sk_family != AF_INET)
		return 0;

	__be32 daddr = 0;
	__be16 dport = 0;
	if (bpf_probe_read_kernel(&daddr, sizeof(daddr),
				  &sk->__sk_common.skc_daddr))
		return 0;
	if (bpf_probe_read_kernel(&dport, sizeof(dport),
				  &sk->__sk_common.skc_dport))
		return 0;
	if (daddr == 0)
		return 0;

	short protocol = 0;
	if (bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk->sk_protocol))
		return 0;
	__u8 proto = (protocol == IPPROTO_UDP) ? COLDSTEP_PROTO_UDP : COLDSTEP_PROTO_TCP;

	if (lsm_dst_in_ignored(daddr))
		return 0;
	if (lsm_dst_is_allowlisted(daddr))
		return 0;

	__u8 addr_bytes[4];
	__builtin_memcpy(addr_bytes, &daddr, sizeof(addr_bytes));
	lsm_emit_deny_event_ipv4(proto, addr_bytes, dport,
				 COLDSTEP_DENY_REASON_DST_NOT_ALLOWLISTED);

	return -EPERM;
}
