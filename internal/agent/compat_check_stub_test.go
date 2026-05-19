//go:build !linux

package agent

import "testing"

func TestCheckRunnerCompat_StubReturnsNil(t *testing.T) {
	t.Parallel()
	if got := CheckRunnerCompat(); got != nil {
		t.Fatalf("non-linux CheckRunnerCompat must return nil, got %+v", got)
	}
}
