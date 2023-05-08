package sourceanalysis

import (
	"path/filepath"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

// vulnsFromAllPkgs returns the flattened list of unique vulnerabilities
func vulnsFromAllPkgs(pkgs []models.PackageVulns) ([]models.Vulnerability, map[string]models.Vulnerability) {
	flatVulns := map[string]models.Vulnerability{}
	for _, pv := range pkgs {
		for _, vuln := range pv.Vulnerabilities {
			flatVulns[vuln.ID] = vuln
		}
	}

	vulns := []models.Vulnerability{}
	for _, v := range flatVulns {
		vulns = append(vulns, v)
	}

	return vulns, flatVulns
}

// Run runs the language specific analyzers on the code given packages and source info
func Run(r reporter.Reporter, source models.SourceInfo, pkgs []models.PackageVulns) ([]models.PackageVulns, error) {
	if source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" {
		return goAnalysis(filepath.Dir(source.Path), pkgs)
	}
	return pkgs, nil
}
