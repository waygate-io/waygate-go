package waygate

import (
	"github.com/jmoiron/sqlx"
	//"github.com/mattn/go-sqlite3"
)

type Forward struct {
	Domain         string `db:"domain"`
	Protected      bool   `db:"protected"`
	TargetAddress  string `db:"target_address"`
	TLSPassthrough bool   `db:"tls_passthrough"`
}

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

type ClientDatabase struct {
	db *sqlx.DB
}

func NewClientDatabase(path string) (*ClientDatabase, error) {
	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	stmt := `
        CREATE TABLE IF NOT EXISTS config(
                server_uri TEXT DEFAULT "" UNIQUE NOT NULL,
                token TEXT DEFAULT "" UNIQUE NOT NULL
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

	stmt = `
        CREATE TABLE IF NOT EXISTS forwards(
                domain TEXT UNIQUE NOT NULL,
                target_address TEXT NOT NULL,
                protected BOOLEAN,
                tls_passthrough BOOLEAN
        );
        `
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	stmt = `
        CREATE TABLE IF NOT EXISTS domains(
                domain TEXT UNIQUE NOT NULL
        );
        `
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	s := &ClientDatabase{
		db: db,
	}

	return s, nil
}

func (d *ClientDatabase) GetServerUri() (string, error) {
	var value string

	stmt := `
        SELECT server_uri FROM config;
        `
	err := d.db.QueryRow(stmt).Scan(&value)
	if err != nil {
		return "", err
	}

	return value, nil
}
func (d *ClientDatabase) SetServerUri(serverUri string) error {
	stmt := `
        UPDATE config SET server_uri=?;
        `
	_, err := d.db.Exec(stmt, serverUri)
	if err != nil {
		return err
	}

	return nil
}

func (d *ClientDatabase) GetToken() (string, error) {
	var value string

	stmt := `
        SELECT token FROM config;
        `
	err := d.db.QueryRow(stmt).Scan(&value)
	if err != nil {
		return "", err
	}

	return value, nil
}
func (d *ClientDatabase) SetToken(value string) error {
	stmt := `
        UPDATE config SET token=?;
        `
	_, err := d.db.Exec(stmt, value)
	if err != nil {
		return err
	}

	return nil
}

func (d *ClientDatabase) GetForwards() ([]*Forward, error) {

	stmt := `
        SELECT * FROM forwards;
        `

	var forwards []*Forward

	err := d.db.Select(&forwards, stmt)
	if err != nil {
		return nil, err
	}

	return forwards, nil
}

func (s *ClientDatabase) GetForward(domain string) (*Forward, error) {

	var forward Forward

	stmt := "SELECT * FROM forwards WHERE domain = ?"
	err := s.db.Get(&forward, stmt, domain)
	if err != nil {
		return nil, err
	}

	return &forward, nil
}

func (d *ClientDatabase) SetForward(f *Forward) error {
	stmt := `
        INSERT OR REPLACE INTO forwards(domain,target_address,protected,tls_passthrough) VALUES(?,?,?,?);
        `
	_, err := d.db.Exec(stmt, f.Domain, f.TargetAddress, f.Protected, f.TLSPassthrough)
	if err != nil {
		return err
	}

	return nil
}

func (d *ClientDatabase) DeleteForwardByDomain(domain string) error {
	stmt := `
        DELETE FROM forwards WHERE domain = ?;
        `
	_, err := d.db.Exec(stmt, domain)
	if err != nil {
		return err
	}

	return nil
}

func (d *ClientDatabase) GetDomains() ([]string, error) {

	stmt := `
        SELECT domain FROM domains;
        `

	var domains []string

	err := d.db.Select(&domains, stmt)
	if err != nil {
		return nil, err
	}

	return domains, nil
}

func (d *ClientDatabase) SetDomain(domain string) error {
	stmt := `
        INSERT OR REPLACE INTO domains(domain) VALUES(?);
        `
	_, err := d.db.Exec(stmt, domain)
	if err != nil {
		return err
	}

	return nil
}
