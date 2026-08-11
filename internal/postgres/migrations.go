package postgres

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var migrationNamePattern = regexp.MustCompile(`^(\d{6})_([a-z0-9_]+)\.sql$`)

type Migration struct {
	Version  int64
	Name     string
	SQL      string
	Checksum string
}

func EmbeddedMigrations() []Migration {
	migrations, err := loadMigrations(migrationFiles)
	if err != nil {
		panic(err)
	}
	return migrations
}

func loadMigrations(files fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := migrationNamePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid migration version in %q", entry.Name())
		}
		if version != int64(len(migrations)+1) {
			return nil, fmt.Errorf("migration sequence is not contiguous at %q", entry.Name())
		}
		contents, err := fs.ReadFile(files, filepath.ToSlash(filepath.Join("migrations", entry.Name())))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		if strings.TrimSpace(string(contents)) == "" {
			return nil, fmt.Errorf("migration %q is empty", entry.Name())
		}
		digest := sha256.Sum256(contents)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     entry.Name(),
			SQL:      string(contents),
			Checksum: hex.EncodeToString(digest[:]),
		})
	}
	if len(migrations) == 0 {
		return nil, fmt.Errorf("no embedded migrations")
	}
	return migrations, nil
}
