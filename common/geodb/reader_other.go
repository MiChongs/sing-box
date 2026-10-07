//go:build !windows

package geodb

import "github.com/oschwald/maxminddb-golang"

// openReader memory-maps the file. Updates replace the file by renaming a
// new one over it, so the mapping keeps reading the old file until Reload
// swaps it out.
func openReader(path string) (*maxminddb.Reader, error) {
	return maxminddb.Open(path)
}
