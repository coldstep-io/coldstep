package telemetry

// Linux errno values returned by tcp_v4_connect (negated when returned
// to BPF kretprobe, i.e. the kernel returns -ETIMEDOUT etc.). These are
// the architecture-independent values; both x86_64 and arm64 use the
// generic uapi/asm-generic/errno*.h numbers for these names.
const (
	errnoEINPROGRESS  = 115
	errnoETIMEDOUT    = 110
	errnoECONNREFUSED = 111
	errnoENETUNREACH  = 101
	errnoEHOSTUNREACH = 113
	errnoENETDOWN     = 100
	errnoEHOSTDOWN    = 112
	errnoEACCES       = 13
	errnoEPERM        = 1
)

// ConnectResultString classifies a tcp_v4_connect return code into a
// coarse label used by the digest TCP KPI breakdown. The kernel returns
// 0 on success and a negative errno on failure; callers pass that value
// through unchanged. EINPROGRESS appears for non-blocking sockets where
// the connection completion is reported via select/poll/epoll later —
// we surface it as a distinct bucket so users don't read it as an
// established connection.
func ConnectResultString(result int32) string {
	if result == 0 {
		return "established"
	}
	e := -result
	switch e {
	case errnoECONNREFUSED:
		return "refused"
	case errnoETIMEDOUT:
		return "timeout"
	case errnoENETUNREACH, errnoEHOSTUNREACH, errnoENETDOWN, errnoEHOSTDOWN:
		return "unreachable"
	case errnoEINPROGRESS:
		return "in_progress"
	case errnoEACCES, errnoEPERM:
		return "denied"
	}
	return "other"
}
