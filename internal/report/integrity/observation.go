package integrity

import (
	"fmt"

	"github.com/coldstep-io/coldstep/internal/report/model"
)

// RequireMinObservationHours returns an error when the JSONL stream's
// wall-clock observation window is shorter than min. min <= 0 disables
// the check. This is the learning-mode-poisoning gate (P1-2 / 4a):
// allowlists derived from very short detect runs are more likely to bake
// in a transient compromise.
//
// The window is computed by model.ObservationWindow (meta-event start
// when available, latest event for end). When the stream has no usable
// timestamps the window is 0h and the check fails.
func RequireMinObservationHours(events []model.Event, min float64) error {
	if min <= 0 {
		return nil
	}
	hours := model.ObservationHours(events)
	if hours < min {
		return fmt.Errorf("observation window %.2fh is shorter than required minimum %.2fh", hours, min)
	}
	return nil
}
