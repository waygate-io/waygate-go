package waygate

import (
	"database/sql"
	"github.com/jmoiron/sqlx"
	//"github.com/mattn/go-sqlite3"
)

type user struct {
	ID string `db:"id"`
}

type Domain struct {
	Domain string `db:"domain"`
	Status string `db:"status"`
}

const DomainStatusPending = "Pending"
const DomainStatusReady = "Ready"

type ClientTunnel struct {
	ServerAddress  string     `db:"server_address"`
	ClientAddress  string     `db:"client_address"`
	Protected      bool       `db:"protected"`
	Type           TunnelType `db:"type"`
	TLSPassthrough bool       `db:"tls_passthrough"`
}

type Database interface {
	GetDomains() ([]Domain, error)
	SetDomain(v Domain) error
	GetACMEEmail() (string, error)
	GetSQLDB() *sql.DB
}

type ServerDatabase struct {
	db *sqlx.DB
}

func NewServerDatabase(path string) (*ServerDatabase, error) {

	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	stmt := `
        CREATE TABLE IF NOT EXISTS config(
		acme_email TEXT UNIQUE DEFAULT ''
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

	err = createUsersTable(db.DB)
	if err != nil {
		return nil, err
	}

	err = createDomainsTable(db.DB)
	if err != nil {
		return nil, err
	}

	s := &ServerDatabase{
		db: db,
	}

	return s, nil
}

func (d *ServerDatabase) GetSQLDB() *sql.DB {
	return d.db.DB
}

func (d *ServerDatabase) GetACMEEmail() (string, error) {
	return getACMEEmail(d.db)
}

func (d *ServerDatabase) GetUsers() ([]user, error) {
	return getUsers(d.db)
}

func (d *ServerDatabase) GetDomains() ([]Domain, error) {
	return getDomains(d.db)
}

func (d *ServerDatabase) SetDomain(v Domain) error {
	return setDomain(d.db, v)
}

func (d *ServerDatabase) DeleteDomain(domain string) error {
	return deleteDomain(d.db, domain)
}

func (d *ServerDatabase) SetUser(v user) error {
	return setUser(d.db, v)
}

func (d *ServerDatabase) SetACMEEmail(val string) error {
	return setACMEEmail(d.db, val)
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
                token TEXT DEFAULT "" UNIQUE NOT NULL,
		acme_email TEXT DEFAULT "" UNIQUE,
		client_name TEXT DEFAULT "" UNIQUE
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

	err = createUsersTable(db.DB)
	if err != nil {
		return nil, err
	}

	err = createDomainsTable(db.DB)
	if err != nil {
		return nil, err
	}

	s := &ClientDatabase{
		db: db,
	}

	return s, nil
}

func (d *ClientDatabase) GetSQLDB() *sql.DB {
	return d.db.DB
}

func (d *ClientDatabase) GetACMEEmail() (string, error) {
	return getACMEEmail(d.db)
}

func (d *ClientDatabase) SetACMEEmail(val string) error {
	return setACMEEmail(d.db, val)
}

func (d *ClientDatabase) GetDomains() ([]Domain, error) {
	return getDomains(d.db)
}

func (d *ClientDatabase) SetDomain(v Domain) error {
	return setDomain(d.db, v)
}

func (d *ClientDatabase) DeleteDomain(domain string) error {
	return deleteDomain(d.db, domain)
}

func (d *ClientDatabase) GetUsers() ([]user, error) {
	return getUsers(d.db)
}

func (d *ClientDatabase) SetUser(v user) error {
	return setUser(d.db, v)
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

func (d *ClientDatabase) GetClientName() (string, error) {
	var value string

	stmt := `
        SELECT client_name FROM config;
        `
	err := d.db.QueryRow(stmt).Scan(&value)
	if err != nil {
		return "", err
	}

	return value, nil
}
func (d *ClientDatabase) SetClientName(value string) error {
	stmt := `
        UPDATE config SET client_name=?;
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

func createUsersTable(db *sql.DB) (err error) {
	stmt := `
        CREATE TABLE IF NOT EXISTS users(
                id TEXT UNIQUE NOT NULL
        );
        `
	_, err = db.Exec(stmt)
	if err != nil {
		return
	}

	return
}

func createDomainsTable(db *sql.DB) (err error) {
	stmt := `
        CREATE TABLE IF NOT EXISTS domains(
                domain TEXT UNIQUE NOT NULL,
		status TEXT NOT NULL
        );
        `
	_, err = db.Exec(stmt)
	if err != nil {
		return
	}

	return
}

func getUsers(db *sqlx.DB) ([]user, error) {
	stmt := `
        SELECT id FROM users;
        `

	var vals []user

	err := db.Select(&vals, stmt)
	if err != nil {
		return nil, err
	}

	return vals, nil
}

func setUser(db *sqlx.DB, v user) error {
	stmt := `
        INSERT OR REPLACE INTO users(id) VALUES(?);
        `
	_, err := db.Exec(stmt, v.ID)
	if err != nil {
		return err
	}

	return nil
}

func getDomains(db *sqlx.DB) ([]Domain, error) {

	stmt := `
        SELECT domain,status FROM domains;
        `

	var domains []Domain

	err := db.Select(&domains, stmt)
	if err != nil {
		return nil, err
	}

	return domains, nil
}

func setDomain(db *sqlx.DB, v Domain) error {
	stmt := `
        INSERT OR REPLACE INTO domains(domain,status) VALUES(?,?);
        `
	_, err := db.Exec(stmt, v.Domain, v.Status)
	if err != nil {
		return err
	}

	return nil
}

func deleteDomain(db *sqlx.DB, domain string) error {
	stmt := `
        DELETE FROM domains WHERE domain = ?;
        `
	_, err := db.Exec(stmt, domain)
	if err != nil {
		return err
	}

	return nil
}

func getACMEEmail(db *sqlx.DB) (string, error) {
	var val string

	stmt := `
        SELECT acme_email FROM config;
        `
	err := db.QueryRow(stmt).Scan(&val)
	if err != nil {
		return "", err
	}

	return val, nil
}

func setACMEEmail(db *sqlx.DB, val string) error {
	stmt := `
        UPDATE config SET acme_email=?;
        `
	_, err := db.Exec(stmt, val)
	if err != nil {
		return err
	}

	return nil
}
