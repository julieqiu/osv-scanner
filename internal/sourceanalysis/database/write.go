package database

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

var (
	indexDir        = "index"
	idDir           = "ID"
	dbEndpoint      = "db.json"
	modulesEndpoint = "modules.json"
)

func (db *Database) Write(dir string) error {
	if err := db.writeIndex(filepath.Join(dir, indexDir)); err != nil {
		return err
	}
	return db.writeEntries(filepath.Join(dir, idDir))
}

func (db *Database) writeIndex(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}
	if err := write(filepath.Join(dir, dbEndpoint), db.DB); err != nil {
		return err
	}
	return write(filepath.Join(dir, modulesEndpoint), db.Modules)
}

func (db *Database) writeEntries(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %s", dir, err)
	}

	for _, entry := range db.Entries {
		if err := write(filepath.Join(dir, entry.ID+".json"), entry); err != nil {
			return err
		}
	}
	return nil
}

func write(filename string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	// Write standard.
	if err := os.WriteFile(filename, b, 0644); err != nil {
		return err
	}
	return nil
}
