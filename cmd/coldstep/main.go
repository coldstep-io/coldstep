package main

import (
	"fmt"
	"os"

	"github.com/coldstep-io/coldstep/internal/agent"
)

// agentMain is swapped in tests to avoid running the real agent.
var agentMain = agent.Main

func main() {
	os.Exit(runCLI(os.Args))
}

func runCLI(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: coldstep <run|validate> [args...]")
		return 2
	}
	switch args[1] {
	case "run":
		if err := agentMain(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		return 0
	case "validate":
		return runValidate(args[2:], os.Stdout, os.Stderr)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		return 2
	}
}
