package waygate

import (
	"context"
	"os"
	"testing"

	"github.com/jmoiron/sqlx"
)

func TestLoadStore(t *testing.T) {

	ctx, s := setup(t)

	err := s.Store(ctx, "key1", []byte{42})
	checkErr(err, t)

	val, err := s.Load(ctx, "key1")
	checkErr(err, t)

	if len(val) == 0 || val[0] != 42 {
		t.Fatal("Wrong value")
	}
}

func TestList(t *testing.T) {

	ctx, s := setup(t)

	err := s.Store(ctx, "a/a", []byte{42})
	checkErr(err, t)

	err = s.Store(ctx, "a/b", []byte{43})
	checkErr(err, t)

	err = s.Store(ctx, "a/a/a", []byte{44})
	checkErr(err, t)

	err = s.Store(ctx, "a/b/a", []byte{45})
	checkErr(err, t)

	recursive := false
	results, err := s.List(ctx, "a", recursive)
	checkErr(err, t)

	if len(results) != 2 {
		t.Fatal("Wrong value")
	}

	recursive = true
	results, err = s.List(ctx, "a", recursive)
	checkErr(err, t)

	if len(results) != 4 {
		t.Fatal("Wrong value")
	}
}

func TestExists(t *testing.T) {

	ctx, s := setup(t)

	exists := s.Exists(ctx, "key1")

	if exists {
		t.Fatal("Wrong value")
	}

	err := s.Store(ctx, "key1", []byte{42})
	checkErr(err, t)

	exists = s.Exists(ctx, "key1")

	if !exists {
		t.Fatal("Wrong value")
	}

	exists = s.Exists(ctx, "key2")

	if exists {
		t.Fatal("Wrong value")
	}
}

func TestStat(t *testing.T) {

	var err error

	ctx, s := setup(t)

	err = s.Store(ctx, "key1", []byte{42})
	checkErr(err, t)

	err = s.Store(ctx, "key2", []byte{42})
	checkErr(err, t)

	val, err := s.Stat(ctx, "key1")
	checkErr(err, t)

	if val.IsTerminal != true {
		t.Fatal("Wrong value")
	}

	err = s.Store(ctx, "key1/a", []byte{42})
	checkErr(err, t)

	val, err = s.Stat(ctx, "key1")
	checkErr(err, t)

	if val.IsTerminal != false {
		t.Fatal("Wrong value")
	}
}

func TestDelete(t *testing.T) {

	ctx, s := setup(t)

	err := s.Store(ctx, "a/a", []byte{42})
	checkErr(err, t)

	err = s.Store(ctx, "a/b", []byte{43})
	checkErr(err, t)

	err = s.Store(ctx, "a/a/a", []byte{44})
	checkErr(err, t)

	err = s.Store(ctx, "a/b/a", []byte{45})
	checkErr(err, t)

	err = s.Delete(ctx, "a/a/a")
	checkErr(err, t)

	recursive := true
	keys, err := s.List(ctx, "", recursive)
	checkErr(err, t)

	if len(keys) != 3 {
		t.Fatalf("Wrong value. Got %d", len(keys))
	}

	err = s.Delete(ctx, "a")
	checkErr(err, t)

	keys, err = s.List(ctx, "", recursive)
	checkErr(err, t)

	if len(keys) != 0 {
		t.Fatalf("Wrong value. Got %d", len(keys))
	}
}

func setup(t *testing.T) (context.Context, *CertmagicSqliteStorage) {
	ctx := context.Background()

	err := os.Remove("test_db.sqlite")
	checkErr(err, t)

	db, err := sqlx.Open("sqlite3", "test_db.sqlite")
	checkErr(err, t)

	s, err := NewCertmagicSqliteStorage(db.DB)
	checkErr(err, t)

	return ctx, s
}

func checkErr(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}
