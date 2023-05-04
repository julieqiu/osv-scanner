package sourceanalysis

import (
	"path/filepath"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/pkg/models"
)

// Run runs the language specific analyzers on the code given packages and source info
func Run(r *output.Reporter, source models.SourceInfo, pkgs []models.PackageVulns) (models.PackageSource, error) {
	if source.Type == "lockfile" && filepath.Base(source.Path) == "go.mod" {
		r, err := goAnalysis(r, pkgs, source)
		if err != nil {
			return *r, nil
		}
		// TODO: what should this return
		return models.PackageSource{}, nil
	}
	return models.PackageSource{Source: source, Packages: pkgs}, nil
}

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
