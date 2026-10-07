// Package geodb shares MaxMind databases (ASN, country) between their
// users and reloads them in place when a download replaces the file, so
// lookups see new data without a restart.
package geodb

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// ErrNotLoaded is returned by lookups while the file has not been loaded,
// typically because its first download has not finished.
var ErrNotLoaded = errors.New("database not loaded")

var (
	access    sync.Mutex
	databases = make(map[string]*Database)
)

// Database is one database file shared by every user that opened its
// path. Lookups run concurrently; a reload waits for the lookups in flight
// before it releases the previous data.
type Database struct {
	path string
	refs int // guarded by access

	readerAccess sync.RWMutex
	reader       *maxminddb.Reader
	closed       bool
}

// Open returns the shared database for path, loading the file for its
// first user. The database is returned even when loading fails: lookups
// return ErrNotLoaded until Reload loads the file. Each Open must be
// paired with one Close.
func Open(path string) (*Database, error) {
	access.Lock()
	database := databases[path]
	if database == nil {
		database = &Database{path: path}
		databases[path] = database
	}
	database.refs++
	access.Unlock()

	database.readerAccess.Lock()
	defer database.readerAccess.Unlock()
	if database.reader != nil {
		return database, nil
	}
	reader, err := openReader(path)
	if err != nil {
		return database, err
	}
	database.reader = reader
	return database, nil
}

// Reload re-reads path for the users that have it open and swaps the new
// data in; when loading fails the previous data stays in use. loaded is
// false when nobody has the path open.
func Reload(path string) (loaded bool, err error) {
	access.Lock()
	database := databases[path]
	access.Unlock()
	if database == nil {
		return false, nil
	}
	return true, database.reload()
}

func (d *Database) reload() error {
	reader, err := openReader(d.path)
	if err != nil {
		return err
	}
	d.readerAccess.Lock()
	if d.closed {
		d.readerAccess.Unlock()
		return reader.Close()
	}
	previous := d.reader
	d.reader = reader
	d.readerAccess.Unlock()
	// No lookup can still be reading previous: they all hold the read
	// lock, which the swap above waited out.
	if previous != nil {
		return previous.Close()
	}
	return nil
}

// Path returns the database file path.
func (d *Database) Path() string {
	return d.path
}

// Loaded reports whether the file has been loaded.
func (d *Database) Loaded() bool {
	d.readerAccess.RLock()
	defer d.readerAccess.RUnlock()
	return d.reader != nil
}

// Lookup decodes the record for ip into result, as maxminddb's Lookup
// does; result is left untouched when the database has no record for ip.
func (d *Database) Lookup(ip netip.Addr, result any) error {
	d.readerAccess.RLock()
	defer d.readerAccess.RUnlock()
	if d.reader == nil {
		return ErrNotLoaded
	}
	return d.reader.Lookup(ip.AsSlice(), result)
}

// Close releases one Open; the last one unloads the file.
func (d *Database) Close() error {
	access.Lock()
	d.refs--
	last := d.refs == 0
	if last && databases[d.path] == d {
		delete(databases, d.path)
	}
	access.Unlock()
	if !last {
		return nil
	}
	d.readerAccess.Lock()
	defer d.readerAccess.Unlock()
	d.closed = true
	if d.reader == nil {
		return nil
	}
	err := d.reader.Close()
	d.reader = nil
	return err
}
