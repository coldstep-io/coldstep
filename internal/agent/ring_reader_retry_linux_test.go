//go:build linux

package agent

import (
	"testing"
	"time"
)

func TestRingReadRetryBackoff_ProgressesAndCaps(t *testing.T) {
	t.Parallel()

	b := newRingReadRetryBackoff()
	var slept []time.Duration
	b.sleepFn = func(d time.Duration) {
		slept = append(slept, d)
	}

	want := []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		160 * time.Millisecond,
		200 * time.Millisecond,
		200 * time.Millisecond,
	}
	for i, wantDelay := range want {
		gotDelay := b.sleep()
		if gotDelay != wantDelay {
			t.Fatalf("sleep() #%d delay=%v want %v", i+1, gotDelay, wantDelay)
		}
	}
	if len(slept) != len(want) {
		t.Fatalf("sleepFn calls=%d want %d", len(slept), len(want))
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("sleepFn delay #%d=%v want %v", i+1, slept[i], want[i])
		}
	}
}

func TestRingReadRetryBackoff_ResetReturnsToBase(t *testing.T) {
	t.Parallel()

	b := newRingReadRetryBackoff()

	if got := b.nextDelay(); got != 5*time.Millisecond {
		t.Fatalf("first delay=%v want %v", got, 5*time.Millisecond)
	}
	if got := b.nextDelay(); got != 10*time.Millisecond {
		t.Fatalf("second delay=%v want %v", got, 10*time.Millisecond)
	}

	b.reset()

	if got := b.nextDelay(); got != 5*time.Millisecond {
		t.Fatalf("delay after reset=%v want %v", got, 5*time.Millisecond)
	}
}
