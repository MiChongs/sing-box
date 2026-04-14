package lightgbm

import "time"

// DefaultModelURL is the mihomo-published LightGBM model.
const DefaultModelURL = "https://github.com/vernesong/mihomo/releases/download/LightGBM-Model/Model-large.bin"

// DefaultUpdateInterval matches mihomo's documented `lgbm-update-interval: 72` (hours).
const DefaultUpdateInterval = 72 * time.Hour
