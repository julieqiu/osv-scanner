// Copied from
// https://github.com/golang/vulndb/blob/480f580aa05fa4dc46cee6fe36776fde968b4f27/internal/database/database.go
// with modifications.
//
// * Database.Vulns is removed because it is not needed.
// * References to golang.org/x/vulndb/internal/osv are replaced with
// github.com/google/osv-scanner/pkg/models.

// Package database provides functionality for reading, writing, and
// validating Go vulnerability databases according to https://go.dev/security/vuln/database#api.
package database

import (
	"encoding/json"
	"time"

	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

// Database represents a Go Vulnerability Database in the v1 schema.
type Database struct {
	// DB represents the index/db.json endpoint.
	DB DBMeta

	// Modules represents the index/modules.json endpoint.
	Modules ModulesIndex

	// Entries represents the ID/GO-YYYY-XXXX.json endpoints.
	Entries []models.Vulnerability
}

// DBMeta contains metadata about the database itself.
type DBMeta struct {
	// Modified is the time the database was last modified, calculated
	// as the most recent time any single OSV entry was modified.
	Modified time.Time `json:"modified"`
}

// ModulesIndex is a map from module paths to module metadata.
// It marshals into and unmarshals from the format published in
// index/modules.json, which is a JSON array of objects.
type ModulesIndex map[string]*Module

func (m ModulesIndex) MarshalJSON() ([]byte, error) {
	modules := maps.Values(m)
	slices.SortFunc(modules, func(m1, m2 *Module) bool {
		return m1.Path < m2.Path
	})
	for _, module := range modules {
		slices.SortFunc(module.Vulns, func(v1, v2 ModuleVuln) bool {
			return v1.ID < v2.ID
		})
	}
	return json.Marshal(modules)
}

// Module contains metadata about a Go module that has one
// or more vulnerabilities in the database.
type Module struct {
	// Path is the module path.
	Path string `json:"path"`
	// Vulns is a list of vulnerabilities that affect this module.
	Vulns []ModuleVuln `json:"vulns"`
}

// ModuleVuln contains metadata about a vulnerability that affects
// a certain module (as used by the ModulesIndex).
type ModuleVuln struct {
	// ID is a unique identifier for the vulnerability.
	// The Go vulnerability database issues IDs of the form
	// GO-<YEAR>-<ENTRYID>.
	ID string `json:"id"`
	// Modified is the time the vuln was last modified.
	Modified time.Time `json:"modified"`
	// Fixed is the latest version that introduces a fix for the
	// vulnerability, in SemVer 2.0.0 format, with no leading "v" prefix.
	// (This is technically the earliest version V such that the
	// vulnerability does not occur in any version later than V.)
	//
	// This field can be used to determine if a version is definitely
	// not affected by a vulnerability (if the version is greater than
	// or equal to the fixed version), but the full OSV entry must
	// be downloaded to determine if a version less than the fixed
	// version is affected.
	//
	// This field is optional, and should be empty if there is no
	// known fixed version.
	//
	// Example:
	// Suppose a vulnerability is present in all versions
	// up to (not including) version 1.5.0, is re-introduced in version
	// 2.0.0, and fixed again in version 2.4.0. The "Fixed" version
	// would be 2.4.0.
	// The fixed version tells us that any version greater than or equal
	// to 2.4.0 is not affected, but we would need to look at the OSV
	// entry to determine if any version less than 2.4.0 was affected.
	Fixed string `json:"fixed,omitempty"`
}
