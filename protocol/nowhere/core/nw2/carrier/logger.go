package carrier

// Logger is internal printf-style plumbing retained inside the carrier package.
// Public configurations accept diagnostic.Observer instead.
type Logger interface {
	Debugf(format string, args ...any)
	Warnf(format string, args ...any)
}

// NopLogger discards all log output.
type NopLogger struct{}

// Debugf discards a debug message.
func (NopLogger) Debugf(string, ...any) {}

// Warnf discards a warning message.
func (NopLogger) Warnf(string, ...any) {}
