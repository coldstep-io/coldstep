package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/coldstep-io/coldstep/internal/report/model"
	"github.com/coldstep-io/coldstep/internal/safepath"
)

func diffSummary(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	current := fs.String("current", envOr("NS_CURRENT", filepath.Join(envOr("GITHUB_WORKSPACE", "."), ".coldstep-events.jsonl")), "")
	baseline := fs.String("baseline", envOr("NS_BASELINE", ""), "")
	summary := fs.String("summary", envOr("NS_SUMMARY", envOr("GITHUB_STEP_SUMMARY", "")), "")
	marker := fs.String("marker", envOr("NS_MARKER", "coldstep-prev-diff"), "")
	// P1-2 / 4c: strict mode. When set, any destination domain that
	// appears in current but not in baseline causes a non-zero exit and
	// is printed to stderr. The intended use is a baseline-diff gate in
	// CI that catches a supply-chain compromise sneaking a new endpoint
	// into the observed surface.
	failOnNewDomain := fs.Bool(
		"fail-on-new-domain",
		false,
		"exit non-zero when current introduces destination domains not in baseline (P1-2 learning-mode-poisoning gate)",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *summary == "" {
		return fmt.Errorf("diff: summary path is required")
	}
	if *baseline == "" {
		return fmt.Errorf("diff: baseline path is required")
	}

	currentPath, err := safepath.Workspace(*current, "NS_CURRENT")
	if err != nil {
		return err
	}
	baselinePath, err := safepath.Workspace(*baseline, "NS_BASELINE")
	if err != nil {
		return err
	}
	summaryPath, err := safepath.Workspace(*summary, "NS_SUMMARY")
	if err != nil {
		return err
	}

	currentEvents, err := model.LoadEvents(currentPath)
	if err != nil {
		return fmt.Errorf("load current events: %w", err)
	}
	baselineEvents, err := model.LoadEvents(baselinePath)
	if err != nil {
		return fmt.Errorf("load baseline events: %w", err)
	}

	diff := model.BuildDiff(currentEvents, baselineEvents)
	if diff.Status != "ok" {
		return fmt.Errorf("diff unavailable: %s", diff.Reason)
	}

	changed := len(diff.TrafficNew) > 0 || len(diff.TrafficGone) > 0 || len(diff.TrafficChanged) > 0
	result := "no-change"
	if changed {
		result = "changed"
	}

	newDomains := newDestinationDomains(currentEvents, baselineEvents)

	f, err := os.OpenFile(summaryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		f,
		"\n#### Previous-run traffic diff (compact)\n\n- %s.result=%s\n- %s.traffic_new=%d\n- %s.traffic_gone=%d\n- %s.traffic_changed=%d\n- %s.new_domains=%d\n",
		*marker,
		result,
		*marker,
		len(diff.TrafficNew),
		*marker,
		len(diff.TrafficGone),
		*marker,
		len(diff.TrafficChanged),
		*marker,
		len(newDomains),
	); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if *failOnNewDomain && len(newDomains) > 0 {
		fmt.Fprintf(
			os.Stderr,
			"::error title=Coldstep new destination domains::%d domain(s) present in current but absent from baseline (P1-2): %s\n",
			len(newDomains),
			strings.Join(newDomains, ", "),
		)
		return fmt.Errorf("diff: %d new destination domain(s) not present in baseline", len(newDomains))
	}
	return nil
}

// newDestinationDomains returns the sorted set of FQDNs (falling back to
// host/sni when fqdn is empty) that appear in current's egress events
// (tcp/udp/http/tls) but never in baseline's. Bare IPs are excluded:
// they are already covered by the traffic_new fingerprint count and
// would create constant churn for runners whose dial-time IPs rotate.
func newDestinationDomains(current, baseline []model.Event) []string {
	base := destinationDomainSet(baseline)
	cur := destinationDomainSet(current)
	out := make([]string, 0)
	for dom := range cur {
		if _, ok := base[dom]; !ok {
			out = append(out, dom)
		}
	}
	sort.Strings(out)
	return out
}

func destinationDomainSet(events []model.Event) map[string]struct{} {
	out := map[string]struct{}{}
	for _, e := range events {
		typ := e.AsString("type")
		switch typ {
		case "tcp", "udp", "http", "tls":
		default:
			continue
		}
		host := strings.TrimSpace(strings.ToLower(firstNonEmpty(e.AsString("fqdn"), e.AsString("host"), e.AsString("sni"))))
		if host == "" {
			continue
		}
		if isBareIP(host) {
			continue
		}
		out[host] = struct{}{}
	}
	return out
}

func firstNonEmpty(args ...string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}

// isBareIP returns true when host is an IPv4 dotted-quad (all digit/dot
// labels, four labels). Cheap heuristic — full ParseIP would also accept
// IPv6 and CIDR variants we never emit here.
func isBareIP(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) != 4 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
		for _, r := range l {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
