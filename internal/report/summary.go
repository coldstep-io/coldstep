package report

import (
	"fmt"
	"os"
)

func AppendJobSummary(path, markdown string) error {
	if path == "" {
		return fmt.Errorf("job summary path is empty")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(markdown)
	return err
}
