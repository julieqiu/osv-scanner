package database

import (
	"github.com/google/osv-scanner/pkg/models"
)

func Create(dir string, vulns []models.Vulnerability) error {
	db := &Database{
		DB:      DBMeta{},
		Modules: make(ModulesIndex),
		Entries: make([]models.Vulnerability, 0, len(vulns)),
	}
	if err := db.Add(vulns...); err != nil {
		return err
	}
	return db.Write(dir)
}
