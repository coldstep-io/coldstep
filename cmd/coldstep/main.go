package main

import (
	"fmt"
	"log"
	"os"

	"github.com/coldstep-io/coldstep/internal/agent"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: coldstep run")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		if err := agent.Main(); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
