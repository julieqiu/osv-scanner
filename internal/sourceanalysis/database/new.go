// Copied from
// https://github.com/golang/vulndb/blob/480f580aa05fa4dc46cee6fe36776fde968b4f27/internal/database/new.go
// with modifications.
//
// * Database.Vulns is removed because it is not needed.
// * References to golang.org/x/vulndb/internal/osv are replaced with
// github.com/google/osv-scanner/pkg/models.
// * References to golang.org/x/vulndb/internal/report.Version are copied to
// this directory.

package database

import (
	"github.com/google/osv-scanner/pkg/models"
)

// New creates a new database from the given entries.
// Errors if there are multiple entries with the same ID.
func New(entries ...models.Vulnerability) (*Database, error) {
	db := &Database{
		DB:      DBMeta{},
		Modules: make(ModulesIndex),
		Entries: make([]models.Vulnerability, 0, len(entries)),
	}
	for _, entry := range entries {
		if err := db.Add(entry); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Add adds new entries to a database, erroring if any of the entries
// is already in the database.
func (db *Database) Add(entries ...models.Vulnerability) error {
	for _, entry := range entries {
		// Only add the entry once we are sure it won't
		// cause an error.
		db.Entries = append(db.Entries, entry)
		db.Modules.add(entry)
		db.DB.add(entry)
	}
	return nil
}

func (dbi *DBMeta) add(entry models.Vulnerability) {
	if entry.Modified.After(dbi.Modified) {
		dbi.Modified = entry.Modified
	}
}

func (m *ModulesIndex) add(entry models.Vulnerability) {
	for _, affected := range entry.Affected {
		modulePath := affected.Package.Name
		if _, ok := (*m)[modulePath]; !ok {
			(*m)[modulePath] = &Module{
				Path:  modulePath,
				Vulns: []ModuleVuln{},
			}
		}
		module := (*m)[modulePath]
		module.Vulns = append(module.Vulns, ModuleVuln{
			ID:       entry.ID,
			Modified: entry.Modified,
			Fixed:    latestFixedVersion(affected.Ranges),
		})
	}
}

func latestFixedVersion(ranges []models.Range) string {
	var latestFixed Version
	for _, r := range ranges {
		if r.Type == models.RangeSemVer {
			for _, e := range r.Events {
				if fixed := Version(e.Fixed); fixed != "" && latestFixed.Before(fixed) {
					latestFixed = fixed
				}
			}
			// If the vulnerability was re-introduced after the latest fix
			// we found, there is no latest fix for this range.
			for _, e := range r.Events {
				if introduced := Version(e.Introduced); introduced != "" && introduced != "0" && latestFixed.Before(introduced) {
					latestFixed = ""
					break
				}
			}
		}
	}
	return string(latestFixed)
}
