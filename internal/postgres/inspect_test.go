package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type staticMetadataSource struct {
	snapshot MetadataSnapshot
	err      error
}

func (s staticMetadataSource) Snapshot(context.Context) (MetadataSnapshot, error) {
	return s.snapshot, s.err
}

func TestInspectorSchemaStates(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	first := Migration{Version: 1, Checksum: strings.Repeat("a", 64)}
	second := Migration{Version: 2, Checksum: strings.Repeat("b", 64)}
	tests := []struct {
		name       string
		snapshot   MetadataSnapshot
		migrations []Migration
		want       SchemaStatus
		version    int64
	}{
		{name: "uninitialized", snapshot: MetadataSnapshot{}, migrations: []Migration{first}, want: SchemaUninitialized},
		{
			name:       "behind",
			snapshot:   MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{{Version: 1, Checksum: first.Checksum, AppliedAt: now}}},
			migrations: []Migration{first, second}, want: SchemaBehind, version: 1,
		},
		{
			name:       "current",
			snapshot:   MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{{Version: 1, Checksum: first.Checksum, AppliedAt: now}}},
			migrations: []Migration{first}, want: SchemaCurrent, version: 1,
		},
		{
			name: "ahead with unknown migration", snapshot: MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{
				{Version: 1, Checksum: first.Checksum, AppliedAt: now},
				{Version: 2, Checksum: second.Checksum, AppliedAt: now},
			}}, migrations: []Migration{first}, want: SchemaAhead, version: 2,
		},
		{name: "empty metadata", snapshot: MetadataSnapshot{TableExists: true, Complete: true}, migrations: []Migration{first}, want: SchemaInvalid},
		{name: "incomplete metadata", snapshot: MetadataSnapshot{TableExists: true, Complete: false}, migrations: []Migration{first}, want: SchemaInvalid},
		{
			name: "version gap", snapshot: MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{
				{Version: 1, Checksum: first.Checksum, AppliedAt: now},
				{Version: 3, Checksum: second.Checksum, AppliedAt: now},
			}}, migrations: []Migration{first, second}, want: SchemaInvalid, version: 1,
		},
		{
			name:       "checksum mismatch",
			snapshot:   MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{{Version: 1, Checksum: strings.Repeat("f", 64), AppliedAt: now}}},
			migrations: []Migration{first}, want: SchemaInvalid, version: 1,
		},
		{
			name:       "missing checksum",
			snapshot:   MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{{Version: 1, AppliedAt: now}}},
			migrations: []Migration{first}, want: SchemaInvalid,
		},
		{
			name:       "missing applied timestamp",
			snapshot:   MetadataSnapshot{TableExists: true, Complete: true, Applied: []AppliedMigration{{Version: 1, Checksum: first.Checksum}}},
			migrations: []Migration{first}, want: SchemaInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspection, err := NewInspector(staticMetadataSource{snapshot: test.snapshot}, test.migrations).Inspect(context.Background())
			if err != nil {
				t.Fatalf("Inspect returned error: %v", err)
			}
			if inspection.Status != test.want || inspection.CurrentVersion != test.version {
				t.Errorf("inspection = %#v, want status %q version %d", inspection, test.want, test.version)
			}
		})
	}
}

func TestInspectorClassifiesQueryError(t *testing.T) {
	inspection, err := NewInspector(staticMetadataSource{err: errors.New("private connection details")}, EmbeddedMigrations()).Inspect(context.Background())
	if inspection.Status != SchemaQueryError {
		t.Errorf("status = %q, want %q", inspection.Status, SchemaQueryError)
	}
	if !errors.Is(err, ErrSchemaQuery) {
		t.Fatalf("error = %v, want ErrSchemaQuery", err)
	}
	if strings.Contains(err.Error(), "private connection details") {
		t.Error("query error leaked source details")
	}
}
