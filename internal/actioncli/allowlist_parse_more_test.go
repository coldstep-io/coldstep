package actioncli

import (
	"reflect"
	"testing"
)

// TestClassifyAllowTokens_Buckets is the exhaustive routing table for the
// unified allow model: plain/wildcard domains -> hosts+domains, IPv4
// literals/CIDRs -> ips, `!`-prefixed IPv4 literals/CIDRs -> ignoredNets, and
// `!`-prefixed non-IP tokens are dropped (no ignore mechanism for hostnames).
func TestClassifyAllowTokens_Buckets(t *testing.T) {
	cases := []struct {
		name   string
		tokens []string
		want   classifiedAllow
	}{
		{
			name:   "plain domain -> hosts and domains",
			tokens: []string{"example.com"},
			want:   classifiedAllow{hosts: []string{"example.com"}, domains: []string{"example.com"}},
		},
		{
			name:   "wildcard domain -> hosts and domains",
			tokens: []string{"*.ubuntu.com"},
			want:   classifiedAllow{hosts: []string{"*.ubuntu.com"}, domains: []string{"*.ubuntu.com"}},
		},
		{
			name:   "ipv4 literal -> ips",
			tokens: []string{"1.1.1.1"},
			want:   classifiedAllow{ips: []string{"1.1.1.1"}},
		},
		{
			name:   "ipv4 cidr -> ips",
			tokens: []string{"10.0.0.0/8"},
			want:   classifiedAllow{ips: []string{"10.0.0.0/8"}},
		},
		{
			name:   "bang cidr -> ignoredNets",
			tokens: []string{"!192.168.0.0/16"},
			want:   classifiedAllow{ignoredNets: []string{"192.168.0.0/16"}},
		},
		{
			name:   "bang literal -> ignoredNets",
			tokens: []string{"!8.8.8.8"},
			want:   classifiedAllow{ignoredNets: []string{"8.8.8.8"}},
		},
		{
			name:   "bang non-ip is dropped (no hostname ignore mechanism)",
			tokens: []string{"!evil.com"},
			want:   classifiedAllow{},
		},
		{
			name:   "blank and whitespace tokens skipped",
			tokens: []string{"", "   ", "\t", "example.com"},
			want:   classifiedAllow{hosts: []string{"example.com"}, domains: []string{"example.com"}},
		},
		{
			name:   "order preserved across buckets",
			tokens: []string{"a.com", "1.2.3.4", "*.b.com", "!10.0.0.0/8", "9.9.9.9"},
			want: classifiedAllow{
				hosts:       []string{"a.com", "*.b.com"},
				domains:     []string{"a.com", "*.b.com"},
				ips:         []string{"1.2.3.4", "9.9.9.9"},
				ignoredNets: []string{"10.0.0.0/8"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAllowTokens(tc.tokens)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("classifyAllowTokens(%q):\n got %+v\nwant %+v", tc.tokens, got, tc.want)
			}
		})
	}
}

// TestClassifyAllowTokens_RegexIsShapeOnly documents that the IPv4 classifier is
// a shape match, not a validity check: out-of-range octets and prefixes still
// route to the ips bucket (downstream policy compilation validates them). This
// pins current behavior so a future tightening is a conscious change.
func TestClassifyAllowTokens_RegexIsShapeOnly(t *testing.T) {
	got := classifyAllowTokens([]string{"999.1.2.3", "1.2.3.4/99"})
	want := classifiedAllow{ips: []string{"999.1.2.3", "1.2.3.4/99"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

// TestParseAllowlistFileBody_CommentsAndSeparators covers comment stripping
// (full-line and inline), blank lines, CRLF, and the space/tab/comma in-line
// token separators.
func TestParseAllowlistFileBody_CommentsAndSeparators(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"full-line comment skipped", "# header\nexample.com\n", []string{"example.com"}},
		{"inline comment stripped", "example.com # trailing note\n", []string{"example.com"}},
		{"blank lines skipped", "\n\n  \nexample.com\n\n", []string{"example.com"}},
		{"crlf trimmed", "a.com\r\nb.com\r\n", []string{"a.com", "b.com"}},
		{"space separated on one line", "a.com b.com c.com\n", []string{"a.com", "b.com", "c.com"}},
		{"tab separated on one line", "a.com\tb.com\n", []string{"a.com", "b.com"}},
		{"comma separated on one line", "a.com,b.com\n", []string{"a.com", "b.com"}},
		{"mixed entries with comment line", "1.1.1.1\n# note\n*.x.com\t!10.0.0.0/8\n", []string{"1.1.1.1", "*.x.com", "!10.0.0.0/8"}},
		{"comment-only line yields nothing", "#only\n", nil},
		{"empty body yields nothing", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAllowlistFileBody([]byte(tc.body))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseAllowlistFileBody(%q):\n got %#v\nwant %#v", tc.body, got, tc.want)
			}
		})
	}
}

// TestSplitAllowInlineTokens_Separators pins the inline `allow:` input split:
// comma, space, newline, tab are all delimiters; blanks are dropped.
func TestSplitAllowInlineTokens_Separators(t *testing.T) {
	got := splitAllowInlineTokens(" a.com, b.com\t1.2.3.4\n*.c.com ,, ")
	want := []string{"a.com", "b.com", "1.2.3.4", "*.c.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

// FuzzParseAllowlistFileBody asserts the allow-file parser never panics on
// arbitrary (potentially hostile) file content — a build step controls the
// allow-file, so crash-safety is a real property.
func FuzzParseAllowlistFileBody(f *testing.F) {
	for _, seed := range []string{
		"", "# c\n", "a.com b.com", "!10.0.0.0/8\n*.x.com",
		"\r\n\t  #\n", "1.2.3.4 # note", string([]byte{0x00, 0x23, 0x0a, 0xff}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		// Must not panic; classification of the result must not panic either.
		_ = classifyAllowTokens(parseAllowlistFileBody([]byte(body)))
	})
}
