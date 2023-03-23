package sourceanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scanner/internal/govulncheckshim"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/result"
	"github.com/google/osv-scanner/pkg/models"
	newgovulncheck "github.com/julieqiu/vuln"
	"golang.org/x/exp/slices"
)

const vulndbcache = "/tmp/osvscanner/vulndb"

func goAnalysis(r *output.Reporter, pkgs []models.PackageVulns, source models.SourceInfo) {
	vulns, vulnsByID := vulnsFromAllPkgs(pkgs)
	fmt.Println("goAnalysis!")
	newapi := os.Getenv("GOVULNCHECK_API_NEW")
	gvcResByVulnID := map[string]*Result{}
	if newapi == "true" {
		fmt.Println("using the new API")
		err := createDBCache(vulnsByID)
		if err != nil {
			r.PrintError(err.Error())
			return
		}
		fmt.Println("created cache")
		reader, writer := io.Pipe()
		cmd := newgovulncheck.Command(context.Background(), "govulncheck", "-json", "./...")
		cmd.Stdout = writer
		cmd.Dir = filepath.Dir(source.Path)
		if err := cmd.Run(); err != nil {
			r.PrintError(err.Error())
			return
		}
		vulns, err := handleJSON(reader)
		if err != nil {
			r.PrintError(err.Error())
			return
		}
		for _, v := range vulns {
			var r *Result
			for _, m := range v.Modules {
				r.Modules = append(r.Modules, &Module{Path: m.Path})
				for _, p := range m.Packages {
					if len(p.CallStacks) > 0 {
						r.Affected = true
					}
				}
			}
			gvcResByVulnID[v.OSV.ID] = r
		}
	} else {
		res, err := govulncheckshim.RunGoVulnCheck(filepath.Dir(source.Path), vulns)
		if err != nil {
			// TODO: Better method to identify the type of error and give advice specific to the error
			r.PrintError(
				fmt.Sprintf("Failed to run code analysis (govulncheck) on '%s' because %s\n"+
					"(the Go toolchain is required)\n", source.Path, err.Error()))

			return
		}
		for _, v := range res.Vulns {
			r := &Result{Affected: v.IsCalled()}
			for _, m := range v.Modules {
				r.Modules = append(r.Modules, &Module{
					Path: m.Path,
				})
			}
			gvcResByVulnID[v.OSV.ID] = r
		}
	}
	matchAnalysisWithPackageVulns(pkgs, gvcResByVulnID, vulnsByID)
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

func matchAnalysisWithPackageVulns(pkgs []models.PackageVulns, gvcResByVulnID map[string]*Result, vulnsByID map[string]models.Vulnerability) {
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

// handleJSON reads the json from the supplied stream and hands the decoded
// output to the handler.
func handleJSON(from io.Reader) ([]*result.Vuln, error) {
	dec := json.NewDecoder(from)
	var vulns []*result.Vuln
	for dec.More() {
		msg := result.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return nil, err
		}
		if msg.Vulnerability != nil {
			vulns = append(vulns, msg.Vulnerability)
		}
	}
	return vulns, nil
}
