/*
 * Compile-time + trivial runtime guard for bpf/deny_event.h packed layout.
 * Uses minimal integer typedefs compatible with Linux wire conventions.
 */
#include <stdint.h>

typedef uint8_t __u8;
typedef uint32_t __u32;

#include "../deny_event.h"

#include <stdlib.h>

int main(void)
{
	/*
	 * Redundant with _Static_assert in the header; ensures translation unit
	 * fails if someone edits only one side.
	 */
	if (sizeof(struct deny_event) != 46)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
