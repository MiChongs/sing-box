package server

import (
	"errors"
	"fmt"
)

type forcedTermination struct {
	cause error
}

func (e *forcedTermination) Error() string {
	if e == nil || e.cause == nil {
		return "nowhere: forced termination"
	}
	return fmt.Sprintf("nowhere: forced termination: %v", e.cause)
}

func (e *forcedTermination) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func markForcedTermination(cause error) error {
	if cause == nil {
		cause = ErrClosed
	}
	if isForcedTermination(cause) {
		return cause
	}
	return &forcedTermination{cause: cause}
}

func isForcedTermination(cause error) bool {
	var forced *forcedTermination
	return errors.As(cause, &forced)
}
