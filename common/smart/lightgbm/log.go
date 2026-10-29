package lightgbm

import (
	"fmt"
	"sync/atomic"
)

// Logger receives the package's diagnostics.
type Logger interface {
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
	Error(args ...any)
}

var logger atomic.Pointer[Logger]

// SetLogger installs the package logger.
func SetLogger(l Logger) {
	if l == nil {
		logger.Store(nil)
		return
	}
	logger.Store(&l)
}

func logf(level int, format string, args ...any) {
	l := logger.Load()
	if l == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	switch level {
	case 0:
		(*l).Debug(message)
	case 1:
		(*l).Info(message)
	case 2:
		(*l).Warn(message)
	default:
		(*l).Error(message)
	}
}

func debugf(format string, args ...any) { logf(0, format, args...) }
func infof(format string, args ...any)  { logf(1, format, args...) }
func warnf(format string, args ...any)  { logf(2, format, args...) }
func errorf(format string, args ...any) { logf(3, format, args...) }
