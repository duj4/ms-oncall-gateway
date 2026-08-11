package postgres

import (
	"context"
	"time"
)

type SchemaStatus string

const (
	SchemaUninitialized SchemaStatus = "uninitialized"
	SchemaBehind        SchemaStatus = "behind"
	SchemaCurrent       SchemaStatus = "current"
	SchemaAhead         SchemaStatus = "ahead"
	SchemaInvalid       SchemaStatus = "invalid"
	SchemaQueryError    SchemaStatus = "query_error"
)

type AppliedMigration struct {
	Version   int64
	Checksum  string
	AppliedAt time.Time
}

type MetadataSnapshot struct {
	TableExists bool
	Complete    bool
	Applied     []AppliedMigration
}

type Inspection struct {
	Status         SchemaStatus
	CurrentVersion int64
	TargetVersion  int64
}

type MetadataSource interface {
	Snapshot(context.Context) (MetadataSnapshot, error)
}

type Inspector struct {
	source     MetadataSource
	migrations []Migration
}

func NewInspector(source MetadataSource, migrations []Migration) *Inspector {
	return &Inspector{source: source, migrations: append([]Migration(nil), migrations...)}
}

func (i *Inspector) Inspect(ctx context.Context) (Inspection, error) {
	snapshot, err := i.source.Snapshot(ctx)
	if err != nil {
		return Inspection{Status: SchemaQueryError, TargetVersion: int64(len(i.migrations))}, safeError(ErrSchemaQuery, "schema inspection")
	}
	return classifySnapshot(snapshot, i.migrations), nil
}

func classifySnapshot(snapshot MetadataSnapshot, migrations []Migration) Inspection {
	result := Inspection{TargetVersion: int64(len(migrations))}
	if !snapshot.TableExists {
		result.Status = SchemaUninitialized
		return result
	}
	if !snapshot.Complete || len(snapshot.Applied) == 0 {
		result.Status = SchemaInvalid
		return result
	}

	for index, applied := range snapshot.Applied {
		expectedVersion := int64(index + 1)
		if applied.Version != expectedVersion || applied.Checksum == "" || applied.AppliedAt.IsZero() {
			result.Status = SchemaInvalid
			return result
		}
		result.CurrentVersion = applied.Version
		if applied.Version <= int64(len(migrations)) && applied.Checksum != migrations[index].Checksum {
			result.Status = SchemaInvalid
			return result
		}
	}

	if result.CurrentVersion > result.TargetVersion {
		result.Status = SchemaAhead
		return result
	}
	if result.CurrentVersion < result.TargetVersion {
		result.Status = SchemaBehind
		return result
	}
	result.Status = SchemaCurrent
	return result
}
