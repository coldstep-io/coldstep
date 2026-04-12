package report

import (
	"fmt"
	"os"
	"strings"
)

// detectReportPreamble is written once when the detect log file is still empty.
// Tuned for GitHub Actions job summaries (GFM + limited HTML). (Double-quoted so inline `…` renders in Markdown.)
const detectReportPreamble = "## Coldstep · detect\n\n" +
	"<p align=\"center\"><strong>eBPF runtime audit trail</strong><br/>\n" +
	"<sub>Process exec plus optional IPv4 TCP (and best-effort DNS names). Detect-only: observe, do not block.</sub></p>\n\n" +
	"> **Reading this table:** each row is one event from this job. **Comm** is the kernel task name (16-byte field), not full argv or binary path.\n\n" +
	"<details>\n<summary><strong>Signal sources</strong></summary>\n\n" +
	"| Kind | Origin |\n|:--|:--|\n" +
	"| **exec** | `sched` / `sched_process_exec` |\n" +
	"| **tcp** | `connect(2)` (IPv4) |\n" +
	"| **fqdn** | Parsed from observed DNS replies (may be missing) |\n" +
	"| **Policy** | Allow-list classification for TCP (`monitor` when lists unset) |\n\n" +
	"</details>\n\n" +
	"| Event | PID | Comm | Remote | Notes | Policy |\n" +
	"|:-----:|----:|:-----|:-------|:------|:-------|\n"

// SanitizeForMarkdown is exported for callers that build table cells outside this package.
func SanitizeForMarkdown(s string) string {
	return sanitizeCell(s)
}

// sanitizeCell keeps Markdown table cells from breaking on pipes, backticks, or newlines.
func sanitizeCell(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "·")
	s = strings.ReplaceAll(s, "`", "'")
	return strings.TrimSpace(s)
}

// FormatDetectExecRow is one GFM table row (no trailing newline).
func FormatDetectExecRow(pid uint32, comm string) string {
	return fmt.Sprintf("| **exec** | `%d` | `%s` | — | — | — |",
		pid, sanitizeCell(comm))
}

// FormatDetectTCPRow is one GFM table row (no trailing newline).
func FormatDetectTCPRow(pid uint32, comm, ip string, port uint16, fqdn string, cleartextHTTP bool, policyDisplay string) string {
	remote := fmt.Sprintf("`%s:%d`", ip, port)
	notes := "—"
	var parts []string
	if fqdn != "" {
		parts = append(parts, fmt.Sprintf("fqdn `%s`", sanitizeCell(fqdn)))
	}
	if cleartextHTTP {
		parts = append(parts, "`cleartext-http`")
	}
	if len(parts) > 0 {
		notes = strings.Join(parts, " · ")
	}
	pol := sanitizeCell(policyDisplay)
	if pol == "" {
		pol = "—"
	}
	return fmt.Sprintf("| **tcp** | `%d` | `%s` | %s | %s | %s |",
		pid, sanitizeCell(comm), remote, notes, pol)
}

// AppendDetectRecord appends one table row. If the file is empty, writes the Coldstep preamble first.
func AppendDetectRecord(path, row string) error {
	if path == "" {
		return fmt.Errorf("job summary path is empty")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		if _, err := f.WriteString(detectReportPreamble); err != nil {
			return err
		}
	}
	if _, err := f.WriteString(row); err != nil {
		return err
	}
	_, err = f.WriteString("\n")
	return err
}
