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
