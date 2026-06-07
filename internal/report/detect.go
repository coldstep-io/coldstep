package report

import "strings"

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
