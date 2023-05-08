// Copied from
// https://github.com/golang/vulndb/blob/480f580aa05fa4dc46cee6fe36776fde968b4f27/internal/report/report.go
// with modifications.

package database

import "golang.org/x/mod/semver"

// Version is an SemVer 2.0.0 semantic version with no leading "v" prefix,
// as used by OSV.
type Version string

// V returns the version with a "v" prefix.
func (v Version) V() string {
	return "v" + string(v)
}

// Before reports whether v < v2.
func (v Version) Before(v2 Version) bool {
	return semver.Compare(v.V(), v2.V()) < 0
}
