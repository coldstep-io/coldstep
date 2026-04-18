package telemetry

import (
	"net/url"
	"regexp"
	"strings"
)

// redactedCredential is written in place of secrets or auth material in URIs (logs / JSONL / digests).
const redactedCredential = "REDACTED"

var sensitiveQueryKeys = map[string]struct{}{
	"access_token": {}, "refresh_token": {}, "id_token": {}, "id_token_hint": {},
	"token": {}, "oauth_token": {}, "oauth_verifier": {},
	"code":          {}, // OAuth 2 authorization code
	"client_secret": {}, "client_assertion": {},
	"api_key": {}, "apikey": {}, "api-key": {},
	"secret": {}, "password": {}, "passwd": {}, "pwd": {},
	"signature": {}, "sig": {},
	"session": {}, "sessionid": {}, "sid": {},
	"state":  {}, // OAuth state (often high-entropy)
	"bearer": {},
	"auth":   {}, "credential": {}, "credentials": {}, "authorization": {},
}

var (
	jwtLikeRE       = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	bearerRE        = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	ghPatRE         = regexp.MustCompile(`\bgh[ps]_[A-Za-z0-9]{20,}\b`)
	stripeKeyRE     = regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]+\b`)
	awsKeyRE        = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	openAIProjKeyRE = regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}\b`)
	googleAPIKeyRE  = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
	sendGridKeyRE   = regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{30,}\b`)
	slackTokenRE    = regexp.MustCompile(`\bxox[abopr]-[A-Za-z0-9-]{10,}\b`)
)

func normQueryKey(k string) string {
	return strings.ToLower(strings.TrimSpace(k))
}

func isSensitiveQueryKey(k string) bool {
	_, ok := sensitiveQueryKeys[normQueryKey(k)]
	return ok
}

// redactCredentialPatterns replaces common secret and auth substrings anywhere in s.
func redactCredentialPatterns(s string) string {
	if s == "" {
		return s
	}
	s = jwtLikeRE.ReplaceAllString(s, redactedCredential)
	s = bearerRE.ReplaceAllString(s, "Bearer "+redactedCredential)
	s = ghPatRE.ReplaceAllString(s, redactedCredential)
	s = stripeKeyRE.ReplaceAllString(s, redactedCredential)
	s = awsKeyRE.ReplaceAllString(s, redactedCredential)
	s = openAIProjKeyRE.ReplaceAllString(s, redactedCredential)
	s = googleAPIKeyRE.ReplaceAllString(s, redactedCredential)
	s = sendGridKeyRE.ReplaceAllString(s, redactedCredential)
	s = slackTokenRE.ReplaceAllString(s, redactedCredential)
	return s
}

// SanitizeRequestURI removes or masks credential-like query parameters and auth-shaped substrings
// in a request path or full URI. Non-auth query keys and normal path segments are preserved.
func SanitizeRequestURI(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	var u *url.URL
	var err error
	if strings.Contains(s, "://") {
		u, err = url.Parse(s)
	} else if strings.HasPrefix(s, "/") {
		u, err = url.Parse("http://_coldstep.invalid" + s)
	} else if strings.Contains(s, "?") && !strings.Contains(s, "://") {
		// Relative path with query (no scheme, no leading slash): parse under a dummy host so
		// sensitive query keys are stripped (paths from ParseHTTPRequestPrefix always start with "/").
		u, err = url.Parse("http://_coldstep.invalid/" + s)
	} else {
		return redactCredentialPatterns(s)
	}
	if err != nil || u == nil {
		return redactCredentialPatterns(s)
	}

	q := u.Query()
	for k := range q {
		if isSensitiveQueryKey(k) {
			for i := range q[k] {
				q[k][i] = redactedCredential
			}
			continue
		}
		for i := range q[k] {
			q[k][i] = redactCredentialPatterns(q[k][i])
		}
	}
	u.RawQuery = q.Encode()

	var out strings.Builder
	if u.Scheme != "" && u.Host != "" && !strings.HasSuffix(u.Host, "_coldstep.invalid") {
		out.WriteString(u.Scheme)
		out.WriteString("://")
		out.WriteString(u.Host)
	}
	out.WriteString(u.Path)
	if u.RawQuery != "" {
		out.WriteByte('?')
		out.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		out.WriteByte('#')
		out.WriteString(redactCredentialPatterns(u.Fragment))
	}
	return redactCredentialPatterns(out.String())
}
