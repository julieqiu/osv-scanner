package database

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scanner/pkg/models"
)

var (
	jan1999  = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	jan2000  = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	jan2002  = time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
	jan2003  = time.Date(2003, 1, 1, 0, 0, 0, 0, time.UTC)
	testOSV1 = models.Vulnerability{
		ID:        "GO-1999-0001",
		Published: jan1999,
		Modified:  jan2000,
		Aliases:   []string{"CVE-1999-1111"},
		Details:   "Some details",
		Affected: []models.Affected{
			{
				Package: models.Package{
					Name:      "stdlib",
					Ecosystem: "Go",
				},
				Ranges: []models.Range{
					{
						Type: "SEMVER",
						Events: []models.Event{
							{Introduced: "0"}, {Fixed: "1.1.0"},
							{Introduced: "1.2.0"},
							{Fixed: "1.2.2"},
						}}},

				EcosystemSpecific: map[string]interface{}{
					"packages": []struct {
						Path    string
						Symbols []string
					}{
						{Path: "package", Symbols: []string{"Symbol"}}}},
			},
		},
		References: []models.Reference{
			{Type: "FIX", URL: "https://example.com/cl/123"},
		}, DatabaseSpecific: map[string]interface{}{
			"url": "https://pkg.go.dev/vuln/GO-1999-0001"},
	}
	testOSV2 = models.Vulnerability{
		ID:        "GO-2000-0002",
		Published: jan2000,
		Modified:  jan2002,
		Aliases:   []string{"CVE-1999-2222"},
		Details:   "Some details",
		Affected: []models.Affected{
			{
				Package: models.Package{
					Name:      "example.com/module",
					Ecosystem: "Go",
				},
				Ranges: []models.Range{
					{
						Type: "SEMVER", Events: []models.Event{{Introduced: "0"},
							{Fixed: "1.2.0"},
						}}},
				EcosystemSpecific: map[string]interface{}{
					"packages": []struct {
						Path    string
						Symbols []string
					}{
						{Path: "example.com/module/package",
							Symbols: []string{"Symbol"},
						}}}}},
		References: []models.Reference{
			{Type: "FIX", URL: "https://example.com/cl/543"},
		}, DatabaseSpecific: map[string]interface{}{"url": "https://pkg.go.dev/vuln/GO-2000-0002"}}
	testOSV3 = models.Vulnerability{
		ID:        "GO-2000-0003",
		Published: jan2000,
		Modified:  jan2003,
		Aliases:   []string{"CVE-1999-3333", "GHSA-xxxx-yyyy-zzzz"},
		Details:   "Some details",
		Affected: []models.Affected{
			{
				Package: models.Package{
					Name:      "example.com/module",
					Ecosystem: "Go",
				},
				Ranges: []models.Range{
					{
						Type: "SEMVER",
						Events: []models.Event{
							{Introduced: "0"}, {Fixed: "1.1.0"},
						}}},
				EcosystemSpecific: map[string]interface{}{
					"packages": []struct {
						Path    string
						Symbols []string
					}{
						{
							Path:    "example.com/module/package",
							Symbols: []string{"Symbol"},
						},
					},
				},
			},
		},
		References: []models.Reference{
			{Type: "FIX", URL: "https://example.com/cl/000"},
		},
		DatabaseSpecific: map[string]interface{}{
			"url": "https://pkg.go.dev/vuln/GO-2000-0003",
		}}
	valid = &Database{
		DB: DBMeta{Modified: jan2003},
		Modules: ModulesIndex{
			"example.com/module": &Module{Path: "example.com/module", Vulns: []ModuleVuln{{ID: "GO-2000-0002", Modified: jan2002, Fixed: "1.2.0"}, {ID: "GO-2000-0003", Modified: jan2003, Fixed: "1.1.0"}}}, "stdlib": &Module{Path: "stdlib", Vulns: []ModuleVuln{{ID: "GO-1999-0001", Modified: jan2000, Fixed: "1.2.2"}}},
		},
		Entries: []models.Vulnerability{testOSV1, testOSV2, testOSV3}}
)

func TestNew(t *testing.T) {
	got, err := New(testOSV1, testOSV2, testOSV3)
	if err != nil {
		t.Fatal(err)
	}
	want := valid
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("New: unexpected diff (-want, +got):\n%v", diff)
	}
}

func TestLatestFixedVersion(t *testing.T) {
	tests := []struct {
		name   string
		ranges []models.Range
		want   string
	}{
		{
			name:   "empty",
			ranges: []models.Range{},
			want:   "",
		},
		{
			name: "no fix",
			ranges: []models.Range{{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{
						Introduced: "0",
					},
				},
			}},
			want: "",
		},
		{
			name: "no latest fix",
			ranges: []models.Range{{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
					{Fixed: "1.0.4"},
					{Introduced: "1.1.2"},
				},
			}},
			want: "",
		},
		{
			name: "unsorted no latest fix",
			ranges: []models.Range{{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Fixed: "1.0.4"},
					{Introduced: "0"},
					{Introduced: "1.1.2"},
					{Introduced: "1.5.0"},
					{Fixed: "1.1.4"},
				},
			}},
			want: "",
		},
		{
			name: "unsorted with fix",
			ranges: []models.Range{{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{
						Fixed: "1.0.0",
					},
					{
						Introduced: "0",
					},
					{
						Fixed: "0.1.0",
					},
					{
						Introduced: "0.5.0",
					},
				},
			}},
			want: "1.0.0",
		},
		{
			name: "multiple ranges",
			ranges: []models.Range{{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{
						Introduced: "0",
					},
					{
						Fixed: "0.1.0",
					},
				},
			},
				{
					Type: models.RangeSemVer,
					Events: []models.Event{
						{
							Introduced: "0",
						},
						{
							Fixed: "0.2.0",
						},
					},
				}},
			want: "0.2.0",
		},
		{
			name: "pseudoversion",
			ranges: []models.Range{{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{
						Introduced: "0",
					},
					{
						Fixed: "0.0.0-20220824120805-abc",
					},
					{
						Introduced: "0.0.0-20230824120805-efg",
					},
					{
						Fixed: "0.0.0-20240824120805-hij",
					},
				},
			}},
			want: "0.0.0-20240824120805-hij",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := latestFixedVersion(test.ranges)
			if got != test.want {
				t.Errorf("latestFixedVersion = %q, want %q", got, test.want)
			}
		})
	}
}
