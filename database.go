package waygate

import (
	"github.com/jmoiron/sqlx"
	//"github.com/mattn/go-sqlite3"
)

type ClientTunnel struct {
	ServerAddress  string `db:"server_address"`
	ClientAddress  string `db:"client_address"`
	Protected      bool   `db:"protected"`
	Type           string `db:"type"`
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
        CREATE TABLE IF NOT EXISTS tunnels(
                server_address TEXT NOT NULL,
                client_address TEXT NOT NULL,
                protected BOOLEAN,
                type TEXT NOT NULL,
                tls_passthrough BOOLEAN,
                UNIQUE(server_address, type) ON CONFLICT REPLACE
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

func (d *ClientDatabase) GetTunnels() ([]*ClientTunnel, error) {

	stmt := `
        SELECT * FROM tunnels;
        `

	var tunnels []*ClientTunnel

	err := d.db.Select(&tunnels, stmt)
	if err != nil {
		return nil, err
	}

	return tunnels, nil
}

func (s *ClientDatabase) GetTunnel(serverAddr string) (*ClientTunnel, error) {

	var tunnel ClientTunnel

	stmt := "SELECT * FROM tunnels WHERE server_address = ?"
	err := s.db.Get(&tunnel, stmt, serverAddr)
	if err != nil {
		return nil, err
	}

	return &tunnel, nil
}

func (d *ClientDatabase) SetTunnel(f *ClientTunnel) error {
	//stmt := `
	//INSERT OR REPLACE INTO tunnels(server_address,client_address,protected,type,tls_passthrough) VALUES(?,?,?,?,?);
	//`
	stmt := `
        INSERT INTO tunnels(server_address,client_address,protected,type,tls_passthrough) VALUES(?,?,?,?,?);
        `
	_, err := d.db.Exec(stmt, f.ServerAddress, f.ClientAddress, f.Protected, f.Type, f.TLSPassthrough)
	if err != nil {
		return err
	}

	return nil
}

func (d *ClientDatabase) DeleteTunnel(tunnelType TunnelType, address string) error {
	stmt := `
        DELETE FROM tunnels WHERE type = ? AND server_address = ?;
        `
	_, err := d.db.Exec(stmt, tunnelType, address)
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
