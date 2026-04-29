package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		exitf("usage: coldstep-report <build-model|assert-integrity|render-summary|render-html|diff|rdns-enrich|otx-enrich|render-ip-summary>")
	}
	switch os.Args[1] {
	case "build-model":
		exitIf(buildModel(os.Args[2:]))
	case "assert-integrity":
		exitIf(assertIntegrity(os.Args[2:]))
	case "render-summary":
		exitIf(notYet("render-summary"))
	case "render-html":
		exitIf(notYet("render-html"))
	case "diff":
		exitIf(notYet("diff"))
	case "rdns-enrich":
		exitIf(notYet("rdns-enrich"))
	case "otx-enrich":
		exitIf(notYet("otx-enrich"))
	case "render-ip-summary":
		exitIf(notYet("render-ip-summary"))
	default:
		exitf("unknown subcommand %q", os.Args[1])
	}
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func mapKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "·")
	return strings.TrimSpace(s)
}

func notYet(name string) error {
	return errors.New("subcommand " + name + " not yet implemented in this plan stage")
}

func exitIf(err error) {
	if err != nil {
		exitf(err.Error())
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
