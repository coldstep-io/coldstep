/*
 * Host-side unit tests for bpf/coldstep_pure.h (shared with BPF via trace_connect_obs.h).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COLDSTEP_PURE_HOST_TEST
#include "../coldstep_pure.h"

static int g_failures;

#define EXPECT_EQ(actual, expected, name)                                                       \
	do {                                                                                      \
		if ((actual) != (expected)) {                                                     \
			fprintf(stderr, "FAIL %s: got %llu want %llu\n", (name),                     \
				(unsigned long long)(actual), (unsigned long long)(expected)); \
			g_failures++;                                                             \
		}                                                                                 \
	} while (0)

#define EXPECT_NE_ZERO(expr, name)                                                              \
	do {                                                                                      \
		if ((expr) == 0) {                                                                \
			fprintf(stderr, "FAIL %s: expected non-zero\n", (name));                      \
			g_failures++;                                                             \
		}                                                                                 \
	} while (0)

#define EXPECT_ZERO(expr, name)                                                                 \
	do {                                                                                      \
		if ((expr) != 0) {                                                                \
			fprintf(stderr, "FAIL %s: expected zero\n", (name));                          \
			g_failures++;                                                             \
		}                                                                                 \
	} while (0)

int main(void)
{
	/* coldstep_syscall_len_u32 */
	EXPECT_EQ((unsigned long)coldstep_syscall_len_u32(0UL), 0UL, "syscall_len zero");
	EXPECT_EQ((unsigned long)coldstep_syscall_len_u32(0xffffffffUL), 0xffffffffUL,
		  "syscall_len low32");
	EXPECT_EQ((unsigned long)coldstep_syscall_len_u32(~0UL), 0xffffffffUL, "syscall_len truncate");

	/* coldstep_probe_user_sz_http */
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_http(0), 0UL, "http_sz 0");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_http(HTTP_PAYLOAD_MAX),
		  (unsigned long)HTTP_PAYLOAD_MAX, "http_sz max");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_http(HTTP_PAYLOAD_MAX + 1),
		  (unsigned long)HTTP_PAYLOAD_MAX, "http_sz over");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_http(0xffffffffu),
		  (unsigned long)HTTP_PAYLOAD_MAX, "http_sz huge");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_http(200), 192UL, "http_sz mask path");

	/* coldstep_probe_user_sz_tls */
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_tls(0), 0UL, "tls_sz 0");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_tls(TLS_PAYLOAD_MAX),
		  (unsigned long)TLS_PAYLOAD_MAX, "tls_sz max");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_tls(TLS_PAYLOAD_MAX + 9),
		  (unsigned long)TLS_PAYLOAD_MAX, "tls_sz over");
	EXPECT_EQ((unsigned long)coldstep_probe_user_sz_tls(0xffffffffu),
		  (unsigned long)TLS_PAYLOAD_MAX, "tls_sz huge");

	/* coldstep_parse_ipv4_sockaddr16 */
	{
		__u8 scratch[16];
		__be16 port = 0;
		__be32 addr = 0;

		memset(scratch, 0, sizeof(scratch));
		scratch[0] = (unsigned char)(AF_INET & 0xff);
		scratch[1] = (unsigned char)((AF_INET >> 8) & 0xff);
		scratch[2] = 0x00;
		scratch[3] = 0x50; /* port 80, network byte order */
		scratch[4] = 0xc0;
		scratch[5] = 0xa8;
		scratch[6] = 0x01;
		scratch[7] = 0x01; /* 192.168.1.1 */
		EXPECT_ZERO(coldstep_parse_ipv4_sockaddr16(scratch, &port, &addr), "sockaddr ok");
		EXPECT_EQ((unsigned long)port, 0x5000UL,
			  "port LE"); /* __be16 compare via numeric */
		EXPECT_EQ((unsigned long)addr, 0x0101a8c0UL, "addr LE");

		scratch[0] = 10;
		scratch[1] = 0;
		EXPECT_NE_ZERO(coldstep_parse_ipv4_sockaddr16(scratch, &port, &addr),
			       "sockaddr reject non inet");
	}

	/* coldstep_parse_ipv6_sockaddr24 (P5) */
	{
		__u8 scratch[24];
		__be16 port = 0;
		__u8 addr[16];

		memset(scratch, 0, sizeof(scratch));
		memset(addr, 0, sizeof(addr));
		scratch[0] = (unsigned char)(AF_INET6 & 0xff);
		scratch[1] = (unsigned char)((AF_INET6 >> 8) & 0xff);
		scratch[2] = 0x01;
		scratch[3] = 0xbb; /* port 443, network byte order */
		/* sin6_flowinfo @4..8 stays zero */
		/* sin6_addr @8..24: 2001:db8::1 */
		scratch[8] = 0x20;
		scratch[9] = 0x01;
		scratch[10] = 0x0d;
		scratch[11] = 0xb8;
		scratch[23] = 0x01;
		EXPECT_ZERO(coldstep_parse_ipv6_sockaddr24(scratch, &port, addr), "sockaddr6 ok");
		EXPECT_EQ((unsigned long)port, 0xbb01UL, "port6 LE");
		EXPECT_EQ((unsigned long)addr[0], 0x20UL, "addr6 byte0");
		EXPECT_EQ((unsigned long)addr[3], 0xb8UL, "addr6 byte3");
		EXPECT_EQ((unsigned long)addr[15], 0x01UL, "addr6 byte15");

		scratch[0] = (unsigned char)(AF_INET & 0xff);
		scratch[1] = 0;
		EXPECT_NE_ZERO(coldstep_parse_ipv6_sockaddr24(scratch, &port, addr),
			       "sockaddr6 reject non inet6");
	}

	/* coldstep_ipv4_is_loopback — input is network byte order: byte 0 is the first octet */
	{
		__be32 addr;
		__u8 bytes_loopback[4] = { 127, 0, 0, 1 };       /* 127.0.0.1 */
		__u8 bytes_stub[4] = { 127, 0, 0, 53 };          /* 127.0.0.53 (systemd-resolved) */
		__u8 bytes_subnet_high[4] = { 127, 255, 255, 255 };
		__u8 bytes_public[4] = { 168, 63, 129, 16 };     /* Azure resolver — NOT loopback */
		__u8 bytes_almost[4] = { 126, 255, 255, 255 };
		__u8 bytes_above[4] = { 128, 0, 0, 1 };
		__u8 bytes_swapped[4] = { 1, 0, 0, 127 };        /* 1.0.0.127 — 127 in LAST octet */

		memcpy(&addr, bytes_loopback, 4);
		EXPECT_NE_ZERO(coldstep_ipv4_is_loopback(addr), "loopback 127.0.0.1");
		memcpy(&addr, bytes_stub, 4);
		EXPECT_NE_ZERO(coldstep_ipv4_is_loopback(addr), "loopback 127.0.0.53 stub");
		memcpy(&addr, bytes_subnet_high, 4);
		EXPECT_NE_ZERO(coldstep_ipv4_is_loopback(addr), "loopback 127.255.255.255");
		memcpy(&addr, bytes_public, 4);
		EXPECT_ZERO(coldstep_ipv4_is_loopback(addr), "not loopback 168.63.129.16");
		memcpy(&addr, bytes_almost, 4);
		EXPECT_ZERO(coldstep_ipv4_is_loopback(addr), "not loopback 126.255.255.255");
		memcpy(&addr, bytes_above, 4);
		EXPECT_ZERO(coldstep_ipv4_is_loopback(addr), "not loopback 128.0.0.1");
		memcpy(&addr, bytes_swapped, 4);
		EXPECT_ZERO(coldstep_ipv4_is_loopback(addr), "not loopback 1.0.0.127");
	}

	/* coldstep_http_prefix_is_request */
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("GET "), "GET ");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("POST"), "POST");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("HEAD"), "HEAD");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("PUT "), "PUT ");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("DELE"), "DELE");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("PATC"), "PATC");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("OPTI"), "OPTI");
	EXPECT_NE_ZERO(coldstep_http_prefix_is_request("CONN"), "CONN");
	EXPECT_EQ((unsigned long)coldstep_http_prefix_is_request("XMXX"), 0UL, "negative prefix");

	if (g_failures != 0) {
		fprintf(stderr, "%d test(s) failed\n", g_failures);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
