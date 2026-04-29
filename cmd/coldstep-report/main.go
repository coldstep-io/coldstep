package main

import (
	"fmt"
	"os"
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
		exitIf(renderSummary(os.Args[2:]))
	case "render-html":
		exitIf(renderHTML(os.Args[2:]))
	case "diff":
		exitIf(diffSummary(os.Args[2:]))
	case "rdns-enrich":
		exitIf(rdnsEnrich(os.Args[2:]))
	case "otx-enrich":
		exitIf(otxEnrich(os.Args[2:]))
	case "render-ip-summary":
		exitIf(renderIPSummary(os.Args[2:]))
	default:
		exitf("unknown subcommand %q", os.Args[1])
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "·")
	return strings.TrimSpace(s)
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
