package sourceanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/sourceanalysis/govulncheck"
	"github.com/google/osv-scanner/pkg/models"
	"golang.org/x/exp/slices"
	"golang.org/x/vuln/scan"
)

const vulndbcache = "/tmp/osvscanner/vulndb"

func goAnalysis(r *output.Reporter, pkgs []models.PackageVulns, source models.SourceInfo) (*models.PackageSource, error) {
	_, vulnsByID := vulnsFromAllPkgs(pkgs)
	gvcResByVulnID := map[string]*Result{}
	err := createDBCache(vulnsByID)
	if err != nil {
		return nil, err
	}
	cmd := scan.Command(context.Background(), "govulncheck", "-C", source.Path, "-json", "./...")
	reader := cmd.StdoutPipe()
	var h *osvHandler
	if err := handleJSON(reader, h); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	for _, f := range h.findings {
		if isCalled(f) {
			// do something
		}
	}
	return matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID), nil
}

// isCalled reports whether the vulnerability is called, therefore
// affecting the target source code or binary.
func isCalled(v *govulncheck.Finding) bool {
	for _, m := range v.Modules {
		for _, p := range m.Packages {
			if len(p.CallStacks) > 0 {
				return true
			}
		}
	}
	return false
}

type osvHandler struct {
	findings []*govulncheck.Finding
}

func (h *osvHandler) Finding(finding *govulncheck.Finding) {
	h.findings = append(h.findings, finding)
}

func handleJSON(from io.Reader, to *osvHandler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := govulncheck.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		to.Finding(msg.Finding)
	}
	return nil
}

func createDBCache(vulnsByID map[string]models.Vulnerability) error {
	// 1. Write vulns to modules.json and to ID/ file.
	if err := os.MkdirAll(vulndbcache, 0755); err != nil {
		return err
	}
	for id, entry := range vulnsByID {
		if err := write(filepath.Join(vulndbcache, id+".json"), entry); err != nil {
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

type Result struct {
	Affected bool
	Modules  []*Module
}

type Module struct {
	Path string
}

func matchAnalysisWithPackageVulns(pkgs []models.PackageVulns, gvcResByVulnID map[string]*Result, vulnsByID map[string]models.Vulnerability) *models.PackageSource {
	fmt.Println("matchAnalysisWithPackageVulns")
	for _, pv := range pkgs {
		// Use index to keep reference to original element in slice
		for groupIdx := range pv.Groups {
			for _, vulnID := range pv.Groups[groupIdx].IDs {
				analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
				if *analysis == nil {
					*analysis = make(map[string]models.AnalysisInfo)
				}

				gvcVuln, ok := gvcResByVulnID[vulnID]
				if !ok { // If vulnerability not found, check if it contain any source information
					fillNotImportedAnalysisInfo(vulnsByID, vulnID, pv, analysis)
					continue
				}
				// Module list is unlikely to be very big, linear search is fine
				containsModule := slices.ContainsFunc(gvcVuln.Modules, func(module *Module) bool {
					return module.Path == pv.Package.Name
				})

				if !containsModule {
					// Code does not import module, so definitely not called
					(*analysis)[vulnID] = models.AnalysisInfo{
						Called: false,
					}
				} else {
					fmt.Println("!!!", vulnID, gvcVuln.Affected)
					// Code does import module, check if it's called
					(*analysis)[vulnID] = models.AnalysisInfo{
						Called: gvcVuln.Affected,
					}
				}
			}
		}
	}
	return nil
}

// fillNotImportedAnalysisInfo checks for any source information in advisories, and sets called to false
func fillNotImportedAnalysisInfo(vulnsByID map[string]models.Vulnerability, vulnID string, pv models.PackageVulns, analysis *map[string]models.AnalysisInfo) {
	for _, v := range vulnsByID[vulnID].Affected {
		// TODO: Compare versions to see if this is the correct affected element
		// ver, err := semantic.Parse(pv.Package.Version, semantic.SemverVersion)
		if v.Package.Name != pv.Package.Name {
			continue
		}
		_, hasImportsField := v.EcosystemSpecific["imports"]
		if hasImportsField {
			// If there is source information, then analysis has been performed, and
			// code does not import the vulnerable package, so definitely not called
			(*analysis)[vulnID] = models.AnalysisInfo{
				Called: false,
			}
		}
	}
}
