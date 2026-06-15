package config

import "testing"

func TestResolveDetectProfile(t *testing.T) {
	tests := []struct {
		name    string
		flag    string
		env     string
		want    string
		wantErr bool
	}{
		{name: "both empty -> standard default", flag: "", env: "", want: "standard"},
		{name: "env only", flag: "", env: "enhanced", want: "enhanced"},
		{name: "flag only", flag: "enhanced", env: "", want: "enhanced"},
		{name: "flag wins over env", flag: "enhanced", env: "standard", want: "enhanced"},
		{name: "flag standard wins over env enhanced", flag: "standard", env: "enhanced", want: "standard"},
		{name: "flag normalized case+space", flag: "  Enhanced  ", env: "", want: "enhanced"},
		{name: "env normalized case+space", flag: "", env: "  STANDARD ", want: "standard"},
		{name: "whitespace flag falls through to env", flag: "   ", env: "enhanced", want: "enhanced"},
		{name: "invalid flag errors", flag: "bogus", env: "", wantErr: true},
		{name: "invalid env errors", flag: "", env: "bogus", wantErr: true},
		{name: "invalid flag errors even with valid env", flag: "bogus", env: "enhanced", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveDetectProfile(tc.flag, tc.env)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveDetectProfile(%q, %q) = %q, want error", tc.flag, tc.env, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveDetectProfile(%q, %q) unexpected error: %v", tc.flag, tc.env, err)
			}
			if got != tc.want {
				t.Fatalf("ResolveDetectProfile(%q, %q) = %q, want %q", tc.flag, tc.env, got, tc.want)
			}
		})
	}
}
