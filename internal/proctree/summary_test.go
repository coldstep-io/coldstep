package proctree

import (
	"strings"
	"testing"
)

func TestFormatForestLines_SimpleChain(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{ParentTGID: 1, ChildTGID: 10, ParentComm: "bash", ChildComm: "sh"},
		{ParentTGID: 10, ChildTGID: 11, ParentComm: "sh", ChildComm: "true"},
	}
	exec := map[uint32]ExecIdentity{
		1:  {Comm: "bash", Exe: "/bin/bash"},
		10: {Comm: "sh", Exe: "/bin/sh"},
		11: {Comm: "true", Exe: "/usr/bin/true"},
	}
	lines := FormatForestLines(edges, exec, 20)
	if len(lines) < 2 {
		t.Fatalf("expected multiple lines: %#v", lines)
	}
	if lines[0] == "" {
		t.Fatalf("empty first line")
	}
}

func TestFormatForestLines_CycleDoesNotHang(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{ParentTGID: 1, ChildTGID: 2, ParentComm: "a", ChildComm: "b"},
		{ParentTGID: 2, ChildTGID: 3, ParentComm: "b", ChildComm: "c"},
		{ParentTGID: 3, ChildTGID: 2, ParentComm: "c", ChildComm: "b"},
	}
	exec := map[uint32]ExecIdentity{
		1: {Comm: "one", Exe: "/1"},
		2: {Comm: "two", Exe: "/2"},
		3: {Comm: "three", Exe: "/3"},
	}
	lines := FormatForestLines(edges, exec, 50)
	if len(lines) < 3 {
		t.Fatalf("expected root + two children lines, got %d: %#v", len(lines), lines)
	}
	if len(lines) > 20 {
		t.Fatalf("cycle walk should stay bounded, got %d lines", len(lines))
	}
}

func TestFormatForestLines_IgnoresSelfEdge(t *testing.T) {
	t.Parallel()
	edges := []Edge{{ParentTGID: 7, ChildTGID: 7, ParentComm: "x", ChildComm: "x"}}
	lines := FormatForestLines(edges, map[uint32]ExecIdentity{7: {Comm: "solo"}}, 10)
	// Self-edge is dropped; no adjacency ⇒ fallback message (not a hang / stack overflow).
	if len(lines) != 1 || !strings.Contains(lines[0], "unable to derive roots") {
		t.Fatalf("unexpected output for self-edge: %#v", lines)
	}
}

func TestFormatForestLines_Truncates(t *testing.T) {
	t.Parallel()
	var edges []Edge
	for i := uint32(2); i <= 50; i++ {
		edges = append(edges, Edge{ParentTGID: 1, ChildTGID: i, ParentComm: "p", ChildComm: "c"})
	}
	lines := FormatForestLines(edges, map[uint32]ExecIdentity{}, 5)
	if len(lines) > 6 {
		t.Fatalf("expected truncation cap, got %d lines", len(lines))
	}
}
