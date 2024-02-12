package waygate

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.ngrok.com/muxado/v2"
)

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

func ConnectConns(downstreamConn net.Conn, upstreamConn net.Conn) {

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

func pipeConns(readConn net.Conn, writeConn net.Conn) {
	_, err := io.Copy(writeConn, readConn)
	if err != nil {
		log.Println("here")
		log.Println(err.Error())
	}

	switch conn := writeConn.(type) {
	case *net.TCPConn:
		log.Println("close TCPConn")
		conn.CloseWrite()
	case *tls.Conn:
		log.Println("close tls.Conn")
		conn.CloseWrite()
	case muxado.Stream:
		log.Println("close muxado.Stream")
		conn.CloseWrite()
	case *ProxyConn:
		log.Println("close ProxyConn")
		conn.CloseWrite()
	default:
		log.Printf("pipeConns close: %T\n", writeConn)
		panic("invalid conn type")
	}
}

func genRandomText(length int) (string, error) {
	const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
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
