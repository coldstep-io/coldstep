package otx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOTXEnricher_Disabled(t *testing.T) {
	e := New("")
	res, err := e.Enrich(context.Background(), "1.2.3.4")
	if err != nil || res != nil {
		t.Fatalf("disabled enricher should be no-op, got (%v, %v)", res, err)
	}
}

func TestOTXEnricher_HTTP200WithPulses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-OTX-API-KEY"); got != "secret" {
			t.Fatalf("missing api key header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"country_code": "US",
			"asn": "AS15169",
			"pulse_info": {
				"count": 5,
				"pulses": [
					{"tags": ["malware", "scanner"]},
					{"tags": ["scanner"]}
				]
			}
		}`))
	}))
	t.Cleanup(srv.Close)

	e := &OTXEnricher{APIKey: "secret", BaseURL: srv.URL, Client: srv.Client()}
	res, err := e.Enrich(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	if res == nil {
		t.Fatal("expected result, got nil")
	}
	if res.IP != "1.2.3.4" || res.Enricher != "otx" {
		t.Fatalf("bad result fields: %#v", res)
	}
	if res.CountryCode != "US" || res.ASN != "AS15169" {
		t.Fatalf("country/asn not populated: %#v", res)
	}
	if res.Score == 0 {
		t.Fatalf("score should be > 0 for 5 pulses, got %v", res.Score)
	}
	tagSet := map[string]bool{}
	for _, tg := range res.Tags {
		tagSet[tg] = true
	}
	if !tagSet["malware"] || !tagSet["scanner"] {
		t.Fatalf("tags missing: %v", res.Tags)
	}
}

func TestOTXEnricher_HTTP200NoPulses_ReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pulse_info":{"count":0}}`))
	}))
	t.Cleanup(srv.Close)

	e := &OTXEnricher{APIKey: "secret", BaseURL: srv.URL, Client: srv.Client()}
	res, err := e.Enrich(context.Background(), "1.2.3.4")
	if err != nil || res != nil {
		t.Fatalf("no pulses should be (nil, nil); got (%v, %v)", res, err)
	}
}

func TestOTXEnricher_HTTPRateLimitedIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	e := &OTXEnricher{APIKey: "secret", BaseURL: srv.URL, Client: srv.Client()}
	_, err := e.Enrich(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected rate-limit error")
	}
}

func TestOTXEnricher_HTTPForbiddenIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	e := &OTXEnricher{APIKey: "secret", BaseURL: srv.URL, Client: srv.Client()}
	_, err := e.Enrich(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected forbidden error")
	}
}

func TestScoreFromPulseCount(t *testing.T) {
	cases := []struct {
		in   int
		want float64
	}{
		{0, 0},
		{1, 0.4},
		{25, 10},
		{100, 10},
	}
	for _, tc := range cases {
		if got := scoreFromPulseCount(tc.in); got != tc.want {
			t.Errorf("scoreFromPulseCount(%d) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
