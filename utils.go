package waygate

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/namedotcom"
)

type connCloseWriter interface {
	net.Conn
	CloseWrite() error
}

type addr struct {
	network string
	address string
}

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.address }

type wrapperConn struct {
	conn       connCloseWriter
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c wrapperConn) CloseWrite() error                  { return c.conn.CloseWrite() }
func (c wrapperConn) Read(p []byte) (int, error)         { return c.conn.Read(p) }
func (c wrapperConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c wrapperConn) Close() error                       { return c.conn.Close() }
func (c wrapperConn) LocalAddr() net.Addr                { return c.localAddr }
func (c wrapperConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c wrapperConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c wrapperConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c wrapperConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func randomOpenPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	addrParts := strings.Split(listener.Addr().String(), ":")
	port, err := strconv.Atoi(addrParts[len(addrParts)-1])
	if err != nil {
		return 0, err
	}

	listener.Close()

	return port, nil
}

func printJson(data interface{}) {
	d, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(d))
}

func ConnectConns(downstreamConn connCloseWriter, upstreamConn connCloseWriter) {

	defer downstreamConn.Close()
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		pipeConns(downstreamConn, upstreamConn)
		wg.Done()
	}()

	go func() {
		pipeConns(upstreamConn, downstreamConn)
		wg.Done()
	}()

	wg.Wait()
}

func pipeConns(readConn net.Conn, writeConn connCloseWriter) {
	_, err := io.Copy(writeConn, readConn)
	if err != nil {
		log.Println(err.Error())
	}

	writeConn.CloseWrite()
	log.Println("CloseWrite:", reflect.TypeOf(writeConn))
}

const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func genRandomText(length int) (string, error) {
	id := ""
	for i := 0; i < length; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		id += string(chars[randIndex.Int64()])
	}
	return id, nil
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) error {
	cookieDomain, err := buildCookieDomain(r.Host)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Domain:   cookieDomain,
		Name:     name,
		Value:    value,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   maxAge,
	}
	http.SetCookie(w, cookie)

	return nil
}

// TODO: I don't think this will work with all TLDs. Probably should be using
// the public suffix list or something
func buildCookieDomain(fullUrl string) (string, error) {
	rootUrlParsed, err := url.Parse(fullUrl)
	if err != nil {
		return "", err
	}
	hostParts := strings.Split(rootUrlParsed.Host, ".")

	if len(hostParts) < 3 {
		// apex domain
		return rootUrlParsed.Host, nil
	} else {
		cookieDomain := strings.Join(hostParts[1:], ".")
		return cookieDomain, nil
	}
}

func addrToHostPort(addr net.Addr) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}

	return host, port, nil
}

func parseIP(ip string) (net.IP, bool, error) {
	parsed := net.ParseIP(ip)

	if parsed == nil {
		return nil, false, errors.New("Invalid IP")
	}

	if parsed.To4() != nil {
		return parsed, true, nil
	} else {
		return parsed, false, nil
	}
}

func getDnsProvider(provider, token, user string) (certmagic.ACMEDNSProvider, error) {
	switch provider {
	case "name.com":
		return &namedotcom.Provider{
			Server: "https://api.name.com",
			Token:  token,
			User:   user,
		}, nil
	default:
		return nil, errors.New("Unsupported DNS provider")
	}
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}
