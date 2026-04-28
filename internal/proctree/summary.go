package proctree

import (
	"fmt"
	"sort"
)

type Edge struct {
	ParentTGID    uint32
	ChildTGID     uint32
	ParentComm    string
	ChildComm     string
	ChildSID      uint32 // v0.3: session leader PID (0 = unknown)
	ChildPidnsNum uint32 // v0.3: PID namespace inode (container boundary)
}

type ExecIdentity struct {
	Comm string
	Exe  string
}

// FormatForestLines renders up to maxLines human-readable tree lines (later edges win on duplicate parent/child).
func FormatForestLines(edges []Edge, exec map[uint32]ExecIdentity, maxLines int) []string {
	if maxLines <= 0 {
		return nil
	}
	execCopy := cloneExec(exec)
	seedExecFromEdges(edges, execCopy)

	type pair struct{ p, c uint32 }
	seen := make(map[pair]struct{})
	adj := make(map[uint32][]uint32)
	for i := len(edges) - 1; i >= 0; i-- {
		e := edges[i]
		p, c := e.ParentTGID, e.ChildTGID
		if p == 0 || c == 0 || p == c {
			continue
		}
		pr := pair{p: p, c: c}
		if _, ok := seen[pr]; ok {
			continue
		}
		seen[pr] = struct{}{}
		adj[p] = append(adj[p], c)
	}
	for p := range adj {
		ch := adj[p]
		sort.Slice(ch, func(i, j int) bool { return ch[i] < ch[j] })
		adj[p] = ch
	}

	childSet := make(map[uint32]struct{})
	for _, e := range edges {
		if e.ChildTGID != 0 {
			childSet[e.ChildTGID] = struct{}{}
		}
	}
	var roots []uint32
	for p := range adj {
		if _, ok := childSet[p]; !ok {
			roots = append(roots, p)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })

	var lines []string

	for _, r := range roots {
		if len(lines) >= maxLines {
			break
		}
		if _, ok := execCopy[r]; !ok {
			execCopy[r] = ExecIdentity{}
		}
		pathSet := make(map[uint32]struct{})
		pathSet[r] = struct{}{}
		lines = append(lines, nodeLine(r, execCopy))
		if len(lines) >= maxLines {
			break
		}

		var emitSubtree func(pid uint32, continuation string)
		emitSubtree = func(pid uint32, continuation string) {
			ch := adj[pid]
			for i, c := range ch {
				if len(lines) >= maxLines {
					return
				}
				if _, dup := pathSet[c]; dup {
					continue
				}
				if _, ok := execCopy[c]; !ok {
					execCopy[c] = ExecIdentity{Comm: edgeChildComm(edges, pid, c)}
				}
				arm := "├── "
				ext := "│   "
				if i == len(ch)-1 {
					arm = "└── "
					ext = "    "
				}
				pathSet[c] = struct{}{}
				lines = append(lines, continuation+arm+nodeLine(c, execCopy))
				if len(lines) >= maxLines {
					delete(pathSet, c)
					return
				}
				emitSubtree(c, continuation+ext)
				delete(pathSet, c)
			}
		}
		emitSubtree(r, "")
	}

	if len(lines) == 0 && len(edges) > 0 {
		return []string{"(unable to derive roots from sampled edges)"}
	}
	return lines
}

func nodeLine(pid uint32, exec map[uint32]ExecIdentity) string {
	id := exec[pid]
	label := fmt.Sprintf("%s(%d)", id.Comm, pid)
	if id.Comm == "" {
		label = fmt.Sprintf("?(%d)", pid)
	}
	if id.Exe != "" {
		return label + " " + id.Exe
	}
	return label
}

func cloneExec(m map[uint32]ExecIdentity) map[uint32]ExecIdentity {
	out := make(map[uint32]ExecIdentity, len(m)+16)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func seedExecFromEdges(edges []Edge, exec map[uint32]ExecIdentity) {
	for _, e := range edges {
		if _, ok := exec[e.ParentTGID]; !ok && e.ParentComm != "" {
			exec[e.ParentTGID] = ExecIdentity{Comm: e.ParentComm}
		}
		if _, ok := exec[e.ChildTGID]; !ok && e.ChildComm != "" {
			exec[e.ChildTGID] = ExecIdentity{Comm: e.ChildComm}
		}
	}
}

func edgeChildComm(edges []Edge, p, c uint32) string {
	for i := len(edges) - 1; i >= 0; i-- {
		e := edges[i]
		if e.ParentTGID == p && e.ChildTGID == c {
			return e.ChildComm
		}
	}
	return ""
}
