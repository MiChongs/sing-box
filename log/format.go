package log

import (
	"context"
	"strconv"
	"strings"
	"time"

	F "github.com/sagernet/sing/common/format"

	"github.com/logrusorgru/aurora"
)

type Formatter struct {
	BaseTime         time.Time
	DisableColors    bool
	DisableTimestamp bool
	FullTimestamp    bool
	TimestampFormat  string
	DisableLineBreak bool
}

// ════════════════ Pre-computed color cache ════════════════
//
// aurora.Colorize uses a 6x6x6 color cube (216 colors) and computes luma per-call
// to pick readable colors. That's 6 float ops + ANSI string formatting EVERY log line.
// We precompute the aurora.Color value for each of the 216 possible ID mod values
// once at startup, then just look up by index.

var idColors [216]aurora.Color

func init() {
	for i := 0; i < 216; i++ {
		color := aurora.Color(i) % 215
		row := uint(color / 36)
		column := uint(color % 36)

		r := float32(row * 51)
		g := float32(column / 6 * 51)
		b := float32((column % 6) * 51)
		luma := 0.2126*r + 0.7152*g + 0.0722*b
		if luma < 60 {
			row = 5 - row
			column = 35 - column
			color = aurora.Color(row*36 + column)
		}
		color += 16
		color = color << 16
		color |= 1 << 14
		idColors[i] = color
	}
}

// colorForID returns the precomputed aurora color for a given log ID.
// Zero arithmetic in hot path.
func colorForID(id uint32) aurora.Color {
	return idColors[uint8(id)%216]
}

// Pre-computed level strings with ANSI color codes (colored) and plain.
// Avoids aurora.XXX().String() allocation on every log call.
var (
	levelColored = [...]string{
		LevelPanic: aurora.Red("PANIC").String(),
		LevelFatal: aurora.Red("FATAL").String(),
		LevelError: aurora.Red("ERROR").String(),
		LevelWarn:  aurora.Yellow("WARN").String(),
		LevelInfo:  aurora.Cyan("INFO").String(),
		LevelDebug: aurora.White("DEBUG").String(),
		LevelTrace: aurora.White("TRACE").String(),
	}
	levelPlain = [...]string{
		LevelPanic: "PANIC",
		LevelFatal: "FATAL",
		LevelError: "ERROR",
		LevelWarn:  "WARN",
		LevelInfo:  "INFO",
		LevelDebug: "DEBUG",
		LevelTrace: "TRACE",
	}
)

func formatLevelFast(level Level, disableColors bool) string {
	idx := int(level)
	if idx < 0 || idx >= len(levelPlain) {
		return strings.ToUpper(FormatLevel(level))
	}
	if disableColors {
		return levelPlain[idx]
	}
	return levelColored[idx]
}

func (f Formatter) Format(ctx context.Context, level Level, tag string, message string, timestamp time.Time) string {
	levelString := formatLevelFast(level, f.DisableColors)
	if tag != "" {
		message = tag + ": " + message
	}
	var id ID
	var hasId bool
	if ctx != nil {
		id, hasId = IDFromContext(ctx)
	}
	if hasId {
		activeDuration := FormatDuration(time.Since(id.CreatedAt))
		if !f.DisableColors {
			// Pre-computed color lookup — zero arithmetic
			message = F.ToString("[", aurora.Colorize(id.ID, colorForID(id.ID)).String(), " ", activeDuration, "] ", message)
		} else {
			message = F.ToString("[", id.ID, " ", activeDuration, "] ", message)
		}
	}
	switch {
	case f.DisableTimestamp:
		message = levelString + " " + message
	case f.FullTimestamp:
		message = timestamp.Format(f.TimestampFormat) + " " + levelString + " " + message
	default:
		message = levelString + "[" + xd(int(timestamp.Sub(f.BaseTime)/time.Second), 4) + "] " + message
	}
	if f.DisableLineBreak {
		if message[len(message)-1] == '\n' {
			message = message[:len(message)-1]
		}
	} else {
		if message[len(message)-1] != '\n' {
			message += "\n"
		}
	}
	return message
}

func (f Formatter) FormatWithSimple(ctx context.Context, level Level, tag string, message string, timestamp time.Time) (string, string) {
	levelString := formatLevelFast(level, f.DisableColors)
	if tag != "" {
		message = tag + ": " + message
	}
	messageSimple := message
	var id ID
	var hasId bool
	if ctx != nil {
		id, hasId = IDFromContext(ctx)
	}
	if hasId {
		activeDuration := FormatDuration(time.Since(id.CreatedAt))
		if !f.DisableColors {
			message = F.ToString("[", aurora.Colorize(id.ID, colorForID(id.ID)).String(), " ", activeDuration, "] ", message)
		} else {
			message = F.ToString("[", id.ID, " ", activeDuration, "] ", message)
		}
		messageSimple = F.ToString("[", id.ID, " ", activeDuration, "] ", messageSimple)
	}
	switch {
	case f.DisableTimestamp:
		message = levelString + " " + message
	case f.FullTimestamp:
		message = timestamp.Format(f.TimestampFormat) + " " + levelString + " " + message
	default:
		message = levelString + "[" + xd(int(timestamp.Sub(f.BaseTime)/time.Second), 4) + "] " + message
	}
	if message[len(message)-1] != '\n' {
		message += "\n"
	}
	return message, messageSimple
}

func xd(value int, x int) string {
	message := strconv.Itoa(value)
	for len(message) < x {
		message = "0" + message
	}
	return message
}

func FormatDuration(duration time.Duration) string {
	if duration < time.Second {
		return F.ToString(duration.Milliseconds(), "ms")
	} else if duration < time.Minute {
		return F.ToString(int64(duration.Seconds()), ".", int64(duration.Seconds()*100)%100, "s")
	} else {
		return F.ToString(int64(duration.Minutes()), "m", int64(duration.Seconds())%60, "s")
	}
}
