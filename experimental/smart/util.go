package smart

import (
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

func defaultDuration(d badoption.Duration, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return time.Duration(d)
}
