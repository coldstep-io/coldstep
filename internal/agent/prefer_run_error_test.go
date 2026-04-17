//go:build linux

package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/coldstep-io/coldstep/internal/telemetry"
)

func errorsEquivalent(a, b error) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Error() == b.Error()
}

func TestPreferRunError_Precedence(t *testing.T) {
	cancelErr := context.Canceled
	plain := errors.New("plain operational")
	denyTCP := newEnforceDenyError(telemetry.DenyEvent{Protocol: "tcp", Dst: "1.2.3.4", Dport: 443})
	denyUDP := newEnforceDenyError(telemetry.DenyEvent{Protocol: "udp", Dst: "8.8.8.8", Dport: 53})

	tests := []struct {
		name    string
		current error
		cand    error
		want    error
	}{
		{"nil current takes candidate", nil, plain, plain},
		{"suppress canceled candidate", plain, cancelErr, plain},
		{"enforce deny replaces plain", plain, denyTCP, denyTCP},
		{"keep plain when current is deny", denyTCP, plain, denyTCP},
		{"enforce deny vs enforce deny keeps current", denyTCP, denyUDP, denyTCP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preferRunError(tt.current, tt.cand)
			if !errorsEquivalent(got, tt.want) {
				t.Fatalf("preferRunError(%v, %v) = %v want %v", tt.current, tt.cand, got, tt.want)
			}
		})
	}
}
