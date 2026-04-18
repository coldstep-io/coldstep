package telemetry

import (
	"strings"
	"testing"
)

func TestSanitizeRequestURI(t *testing.T) {
	t.Parallel()
	ghPat := "ghp_" + strings.Repeat("a", 20)
	awsKey := "AKIA" + strings.Repeat("0", 16)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace_only", "   \t\n", ""},
		{"path_only", "/v1/resource", "/v1/resource"},
		{"path_trailing_space_trimmed", "  /ok  ", "/ok"},
		{"preserves_non_secret_query", "/search?q=hello+world&page=2", "/search?page=2&q=hello+world"},
		{"token_query_key", "/x?token=secret", "/x?token=REDACTED"},
		{"access_token", "/cb?access_token=sekret&next=1", "/cb?access_token=REDACTED&next=1"},
		{"refresh_token", "/x?refresh_token=r", "/x?refresh_token=REDACTED"},
		{"id_token", "/x?id_token=i", "/x?id_token=REDACTED"},
		{"id_token_hint", "/x?id_token_hint=h", "/x?id_token_hint=REDACTED"},
		{"oauth_token", "/x?oauth_token=ot", "/x?oauth_token=REDACTED"},
		{"oauth_verifier", "/x?oauth_verifier=ov", "/x?oauth_verifier=REDACTED"},
		{"code", "/x?code=c", "/x?code=REDACTED"},
		{"client_secret", "/x?client_secret=s", "/x?client_secret=REDACTED"},
		{"client_assertion", "/x?client_assertion=a", "/x?client_assertion=REDACTED"},
		{"api_key", "/x?api_key=k", "/x?api_key=REDACTED"},
		{"apikey", "/x?apikey=k", "/x?apikey=REDACTED"},
		{"api_key_hyphen", "/x?api-key=k", "/x?api-key=REDACTED"},
		{"secret", "/x?secret=s", "/x?secret=REDACTED"},
		{"password", "/x?password=p", "/x?password=REDACTED"},
		{"passwd", "/x?passwd=p", "/x?passwd=REDACTED"},
		{"pwd", "/x?pwd=p", "/x?pwd=REDACTED"},
		{"signature", "/x?signature=s", "/x?signature=REDACTED"},
		{"sig", "/x?sig=s", "/x?sig=REDACTED"},
		{"session", "/x?session=s", "/x?session=REDACTED"},
		{"sessionid", "/x?sessionid=s", "/x?sessionid=REDACTED"},
		{"sid", "/x?sid=s", "/x?sid=REDACTED"},
		{"state", "/x?state=st", "/x?state=REDACTED"},
		{"bearer_key", "/x?bearer=t", "/x?bearer=REDACTED"},
		{"auth_query_key", "/x?auth=tok", "/x?auth=REDACTED"},
		{"credential_query_key", "/x?credential=c", "/x?credential=REDACTED"},
		{"credentials_query_key", "/x?credentials=c", "/x?credentials=REDACTED"},
		{"authorization_query_key", "/x?authorization=basic", "/x?authorization=REDACTED"},
		{"query_key_case_insensitive", "/x?TOKEN=secret", "/x?TOKEN=REDACTED"},
		{"jwt_in_non_secret_value", "/p?x=eyJhbGciOiJIUzI1NiJ9.e30.signature", "/p?x=REDACTED"},
		{
			"full_url_https",
			"https://example.com/hook?sig=deadbeef&kind=ping",
			"https://example.com/hook?kind=ping&sig=REDACTED",
		},
		{
			"fragment_jwt",
			"https://ex.example/p#eyJhbGciOiJIUzI1NiJ9.e30.signature",
			"https://ex.example/p#REDACTED",
		},
		{
			"path_with_bearer_substring",
			"/x?q=Bearer+deadbeef+more",
			"/x?q=Bearer+REDACTED+more",
		},
		{"github_pat_in_query", "/x?ref=" + ghPat, "/x?ref=" + redactedCredential},
		{"stripe_sk_test_in_query", "/x?k=sk_test_1234567890", "/x?k=" + redactedCredential},
		{"stripe_sk_live_in_query", "/x?k=sk_live_ABCDEFGHIJ", "/x?k=" + redactedCredential},
		{"aws_access_key_in_query", "/x?k=" + awsKey, "/x?k=" + redactedCredential},
		{
			"openai_proj_key_in_query",
			"/x?k=sk-proj-" + strings.Repeat("a", 24),
			"/x?k=" + redactedCredential,
		},
		{
			"google_api_key_in_query",
			"/x?k=AIza" + strings.Repeat("0", 35),
			"/x?k=" + redactedCredential,
		},
		{
			"sendgrid_key_in_query",
			"/x?k=SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43),
			"/x?k=" + redactedCredential,
		},
		{
			"ghs_pat",
			"/x?t=ghs_" + strings.Repeat("b", 20),
			"/x?t=" + redactedCredential,
		},
		{
			"bare_string_jwt_only",
			"eyJhbGciOiJIUzI1NiJ9.e30.signature",
			redactedCredential,
		},
		{
			"relative_no_leading_slash_query_redacted",
			"relative?token=still-visible",
			"/relative?token=REDACTED",
		},
		{
			"userinfo_omitted_password_not_echoed",
			"https://user:supersecret@host.example/path?ok=1",
			"https://host.example/path?ok=1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := SanitizeRequestURI(tc.in)
			if got != tc.want {
				t.Fatalf("SanitizeRequestURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactPathForSummary_matchesSanitizeRequestURI(t *testing.T) {
	t.Parallel()
	probes := []string{
		"/x?token=secret",
		"/api?page=1&token=secret",
		"https://example.com/h?sig=1",
		"",
		"eyJhbGciOiJIUzI1NiJ9.e30.signature",
	}
	for _, p := range probes {
		if got, want := RedactPathForSummary(p), SanitizeRequestURI(p); got != want {
			t.Fatalf("RedactPathForSummary(%q)=%q SanitizeRequestURI=%q", p, got, want)
		}
	}
}
