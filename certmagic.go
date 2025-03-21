// Code in this file was adapted from https://github.com/crmejia/certmagic-sqlite3
package waygate

import (
	"context"
	"database/sql"
	"errors"
	iofs "io/fs"
	"path/filepath"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/jmoiron/sqlx"
)

type CertmagicSqliteStorage struct {
	db    *sqlx.DB
	mu    *sync.Mutex
	locks map[string]*sync.Mutex
}

type kv struct {
	Key   string `db:"key"`
	Value []byte `db:"value"`
}

func NewCertmagicSqliteStorage(sqlDb *sql.DB) (*CertmagicSqliteStorage, error) {

	db := sqlx.NewDb(sqlDb, "sqlite3")

	s := &CertmagicSqliteStorage{
		db:    db,
		mu:    &sync.Mutex{},
		locks: make(map[string]*sync.Mutex),
	}

	stmt := `
        CREATE TABLE IF NOT EXISTS kv(
                key TEXT NOT NULL PRIMARY KEY,
                value BLOB NOT NULL
        );
        `
	_, err := db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *CertmagicSqliteStorage) Store(ctx context.Context, key string, value []byte) error {

	stmt := `
        INSERT OR REPLACE INTO kv(key, value) VALUES(?, ?);
        `
	_, err := s.db.ExecContext(ctx, stmt, key, value)
	if err != nil {
		return err
	}

	return nil
}

func (s *CertmagicSqliteStorage) Load(ctx context.Context, key string) ([]byte, error) {

	var value []byte

	stmt := `
        SELECT value FROM kv WHERE key=?;
        `
	err := s.db.QueryRowContext(ctx, stmt, key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, iofs.ErrNotExist
		}
		return nil, err
	}

	return value, nil
}

func (s *CertmagicSqliteStorage) Exists(ctx context.Context, key string) bool {

	var value bool

	stmt := `
        SELECT count(*) FROM kv WHERE key GLOB ? || '*';
        `
	err := s.db.QueryRowContext(ctx, stmt, key).Scan(&value)
	if err != nil {
		return false
	}

	return value
}

func (s *CertmagicSqliteStorage) Delete(ctx context.Context, key string) error {

	stmt := `
        DELETE FROM kv WHERE key GLOB ? || '*';
        `
	result, err := s.db.ExecContext(ctx, stmt, key)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return iofs.ErrNotExist
	}

	return nil
}

func (s *CertmagicSqliteStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {

	stmt := `
        SELECT key FROM kv WHERE key GLOB ? || '*';
        `

	var results []string

	err := s.db.SelectContext(ctx, &results, stmt, prefix)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, iofs.ErrNotExist
		}
		return nil, err
	}

	if !recursive {
		pruned := []string{}
		for _, key := range results {
			if filepath.Dir(key) == prefix {
				pruned = append(pruned, key)
			}
		}

		return pruned, nil
	}

	return results, nil
}

func (s *CertmagicSqliteStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {

	ki := certmagic.KeyInfo{}

	recursive := true
	keys, err := s.List(ctx, key, recursive)
	if err != nil {
		return ki, err
	}

	isTerminal := true
	if len(keys) > 1 {
		isTerminal = false
	}

	ki = certmagic.KeyInfo{
		Key:        key,
		IsTerminal: isTerminal,
	}

	return ki, nil
}

func (s *CertmagicSqliteStorage) Lock(ctx context.Context, name string) error {

	s.mu.Lock()
	lock, exists := s.locks[name]
	s.mu.Unlock()
	if !exists {
		lock = &sync.Mutex{}
		s.mu.Lock()
		s.locks[name] = lock
		s.mu.Unlock()
	}

	lock.Lock()

	return nil
}

func (s *CertmagicSqliteStorage) Unlock(ctx context.Context, name string) error {

	s.mu.Lock()
	lock, exists := s.locks[name]
	s.mu.Unlock()
	if !exists {
		return errors.New("No lock for " + name)
	}

	lock.Unlock()

	return nil
}

var (
	_ certmagic.Storage = (*CertmagicSqliteStorage)(nil)
)
