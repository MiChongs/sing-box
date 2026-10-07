package geodb

import (
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// openReader loads the file into memory. A memory-mapped file cannot be
// replaced on Windows, which would make every update of it fail.
func openReader(path string) (*maxminddb.Reader, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return maxminddb.FromBytes(content)
}
