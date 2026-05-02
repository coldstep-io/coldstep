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
	_, werr := f.WriteString(markdown)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
