//go:build linux

package agent

import (
	"sync"

	"github.com/cilium/ebpf/ringbuf"
)

// ringReader wraps a *ringbuf.Reader so it can be closed exactly once from
// multiple paths (the shutdown goroutine plus deferred cleanups). The zero
// value is valid; Close is a no-op until R is set, and remains nil-safe.
type ringReader struct {
	R    *ringbuf.Reader
	once sync.Once
}

func (r *ringReader) Close() {
	r.once.Do(func() {
		if r.R != nil {
			_ = r.R.Close()
		}
	})
}
