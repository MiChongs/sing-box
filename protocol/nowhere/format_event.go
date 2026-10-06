package nowhere

import "github.com/sagernet/sing-box/protocol/nowhere/core/diagnostic"

func formatDiagnosticEvent(event diagnostic.Event) string {
	return diagnostic.FormatEvent(event)
}
