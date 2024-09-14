// Code in this file was adapted from https://github.com/crmejia/certmagic-sqlite3
package waygate

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

type kvStore struct {
	db *sqlx.DB
}

func NewKvStore(sqlDb *sql.DB) (*kvStore, error) {

	db := sqlx.NewDb(sqlDb, "sqlite3")

	s := &kvStore{
		db: db,
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

func (s *kvStore) Set(key string, value []byte) error {

	stmt := `
        INSERT OR REPLACE INTO kv(key, value) VALUES(?, ?);
        `
	_, err := s.db.Exec(stmt, key, value)
	if err != nil {
		return err
	}

	return nil
}

func (s *kvStore) Get(key string) ([]byte, error) {

	var value []byte

	stmt := `
        SELECT value FROM kv WHERE key=?;
        `
	err := s.db.QueryRow(stmt, key).Scan(&value)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (s *kvStore) Delete(key string) error {

	stmt := `
        DELETE FROM kv WHERE key=?;
        `
	_, err := s.db.Exec(stmt, key)
	if err != nil {
		return err
	}

	return nil
}
