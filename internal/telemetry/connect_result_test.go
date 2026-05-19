package telemetry

import "testing"

func TestConnectResultString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result int32
		want   string
	}{
		{"success", 0, "established"},
		{"refused", -111, "refused"},
		{"timeout", -110, "timeout"},
		{"net_unreachable", -101, "unreachable"},
		{"host_unreachable", -113, "unreachable"},
		{"net_down", -100, "unreachable"},
		{"host_down", -112, "unreachable"},
		{"in_progress", -115, "in_progress"},
		{"eperm", -1, "denied"},
		{"eacces", -13, "denied"},
		{"other_negative", -22, "other"},
		{"positive_unexpected", 42, "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConnectResultString(tc.result); got != tc.want {
				t.Fatalf("ConnectResultString(%d) = %q, want %q", tc.result, got, tc.want)
			}
		})
	}
}
