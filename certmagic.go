// Code in this file was adapted from https://github.com/crmejia/certmagic-sqlite3
package waygate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	iofs "io/fs"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/jmoiron/sqlx"
)

type CertmagicSqliteStorage struct {
	db *sqlx.DB
	mu *sync.Mutex
}

type kv struct {
	Key   string `db:"key"`
	Value []byte `db:"value"`
}

func NewCertmagicSqliteStorage(sqlDb *sql.DB) (*CertmagicSqliteStorage, error) {

	db := sqlx.NewDb(sqlDb, "sqlite3")

	s := &CertmagicSqliteStorage{
		db: db,
		mu: &sync.Mutex{},
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
	fmt.Println("Store", key, len(value))

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
	fmt.Println("Load", key)

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

	fmt.Println(len(value))

	return value, nil
}

func (s *CertmagicSqliteStorage) Exists(ctx context.Context, key string) bool {
	fmt.Println("Exists", key)

	var value bool

	stmt := `
        SELECT count(*) FROM kv WHERE key GLOB '?*';
        `
	err := s.db.QueryRowContext(ctx, stmt, key).Scan(&value)
	if err != nil {
		return false
	}

	fmt.Println(value)

	return value
}

func (s *CertmagicSqliteStorage) Delete(ctx context.Context, key string) error {
	fmt.Println("Delete", key)

	stmt := `
        DELETE FROM kv WHERE key = ?;
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

	fmt.Println("deleted")

	return nil
}

func (s *CertmagicSqliteStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	fmt.Println("List", prefix, recursive)

	stmt := `
        SELECT key FROM kv;
        `

	var results []string

	err := s.db.SelectContext(ctx, &results, stmt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, iofs.ErrNotExist
		}
		return nil, err
	}

	fmt.Println(results)

	return results, nil
}

func (s *CertmagicSqliteStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	fmt.Println("Stat")
	return certmagic.KeyInfo{}, errors.New("Not implemented")
}

func (s *CertmagicSqliteStorage) Lock(ctx context.Context, name string) error {
	fmt.Println("Lock")

	s.mu.Lock()

	fmt.Println("locked")

	return nil
}

func (s *CertmagicSqliteStorage) Unlock(ctx context.Context, name string) error {
	fmt.Println("Unlock")

	s.mu.Unlock()

	fmt.Println("unlocked")

	return nil
}

var (
	_ certmagic.Storage = (*CertmagicSqliteStorage)(nil)
)
