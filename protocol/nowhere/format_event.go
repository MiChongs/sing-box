package nowhere

import "github.com/sagernet/sing-box/protocol/nowhere/core/nw2/diagnostic"

func formatDiagnosticEvent(event diagnostic.Event) string {
	return diagnostic.FormatEvent(event)
}
