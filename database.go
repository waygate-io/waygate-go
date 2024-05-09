package waygate

import (
	"github.com/jmoiron/sqlx"
	//"github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sqlx.DB
}

func NewDatabase(path string) (*Database, error) {

	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	stmt := `
        CREATE TABLE IF NOT EXISTS config(
                jwks_json TEXT UNIQUE
        );
        `
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	stmt = `
        SELECT COUNT(*) FROM config;
        `
	var numRows int
	err = db.QueryRow(stmt).Scan(&numRows)
	if err != nil {
		return nil, err
	}

	if numRows == 0 {
		stmt = `
                INSERT INTO config DEFAULT VALUES;
                `
		_, err = db.Exec(stmt)
		if err != nil {
			return nil, err
		}
	}

	s := &Database{
		db: db,
	}

	return s, nil
}

func (d *Database) GetJWKS() (string, error) {
	var jwks_json string

	stmt := `
        SELECT jwks_json FROM config;
        `
	err := d.db.QueryRow(stmt).Scan(&jwks_json)
	if err != nil {
		return "", err
	}

	return jwks_json, nil
}

func (d *Database) SetJWKS(jwks string) error {
	stmt := `
        UPDATE config SET jwks_json=?;
        `
	_, err := d.db.Exec(stmt, jwks)
	if err != nil {
		return err
	}

	return nil
}
