package waygate

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/namedotcom"
	//"github.com/libdns/route53"
	"github.com/libdns/libdns"
	proxyproto "github.com/pires/go-proxyproto"
	//"github.com/takingnames/namedrop-libdns"
	"go.uber.org/zap"
)

type DNSProvider interface {
	libdns.ZoneLister
	libdns.RecordGetter
	libdns.RecordSetter
	libdns.RecordAppender
	libdns.RecordDeleter
}

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
	fmt.Fprintln(os.Stderr, string(d))
}

func ConnectConns(downstreamConn connCloseWriter, upstreamConn connCloseWriter) {

	terminate := func() {
		err := downstreamConn.Close()
		if err != nil {
			log.Println("ConnectConns: downstreamConn.Close()", err)
		}
		err = upstreamConn.Close()
		if err != nil {
			log.Println("ConnectConns: upstreamConn.Close()", err)
		}
	}

	defer terminate()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		err := pipeConns(downstreamConn, upstreamConn)
		if err != nil {
			log.Println("ConnectConns pipeConns(downstreamConn, upstreamConn)", err.Error())
			terminate()
		}
		wg.Done()
	}()

	go func() {
		err := pipeConns(upstreamConn, downstreamConn)
		if err != nil {
			log.Println("ConnectConns pipeConns(upstreamConn, downstreamConn)", err.Error())
			terminate()
		}
		wg.Done()
	}()

	wg.Wait()
}

func pipeConns(readConn net.Conn, writeConn connCloseWriter) error {
	_, err := io.Copy(writeConn, readConn)
	if err != nil {
		return err
	}

	err = writeConn.CloseWrite()
	if err != nil {
		return err
	}

	return nil
	//log.Println("CloseWrite:", reflect.TypeOf(writeConn))
}

// const chars string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const chars string = "0123456789abcdefghijklmnopqrstuvwxyz"

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

func getDnsProvider(provider, token, user string) (DNSProvider, error) {
	switch provider {
	//case "takingnames":
	//	return &namedrop.Provider{
	//		Token: token,
	//	}, nil
	case "name.com":
		return &namedotcom.Provider{
			Server: "https://api.name.com",
			Token:  token,
			User:   user,
		}, nil
	//case "route53":
	//	return &route53.Provider{
	//		WaitForPropagation: true,
	//		MaxWaitDur:         5 * time.Minute,
	//		// AccessKeyId and SecretAccessKey are grabbed from the environment
	//		//AccessKeyId:     user,
	//		//SecretAccessKey: token,
	//	}, nil
	default:
		return nil, errors.New("Invalid DNS provider")
		//if !strings.HasPrefix(provider, "https://") {
		//	return nil, fmt.Errorf("Assuming NameDrop DNS provider, but %s is not a valid NameDrop server URI", provider)
		//}
		//// Assume provider is a NameDrop URI if nothing else matches
		//return &namedrop.Provider{
		//	ServerUri: provider,
		//	Token:     token,
		//}, nil
	}
}

func ExitOnError(err error) {
	exitOnError(err)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func buildProxyProtoHeader(conn net.Conn, serverName string) (*proxyproto.Header, error) {

	host, port, err := addrToHostPort(conn.RemoteAddr())
	if err != nil {
		return nil, err
	}

	localHost, localPort, err := addrToHostPort(conn.LocalAddr())
	if err != nil {
		return nil, err
	}

	remoteIp, isIPv4, err := parseIP(host)
	if err != nil {
		return nil, err
	}

	localIp, _, err := parseIP(localHost)
	if err != nil {
		return nil, err
	}

	transportProto := proxyproto.TCPv4
	if !isIPv4 {
		transportProto = proxyproto.TCPv6
	}

	proxyHeader := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: transportProto,
		SourceAddr: &net.TCPAddr{
			IP:   remoteIp,
			Port: port,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   localIp,
			Port: localPort,
		},
	}

	if serverName != "" {
		proxyHeader.SetTLVs([]proxyproto.TLV{
			proxyproto.TLV{
				Type:  proxyproto.PP2_TYPE_MIN_CUSTOM,
				Value: []byte(serverName),
			},
		})
	}

	return proxyHeader, nil
}

func exit(w http.ResponseWriter, r *http.Request, tmpl *template.Template, httpServer *http.Server) {

	tmplData := struct {
	}{}

	err := tmpl.ExecuteTemplate(w, "shutdown.html", tmplData)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	go func() {
		err = httpServer.Shutdown(r.Context())
		fmt.Println(err)
	}()
}

func prompt(promptText string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(promptText)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func pointDomainAtDomain(ctx context.Context, dnsProvider DNSProvider, host, domain, targetDomain string) (err error) {

	recordType := "ANAME"
	wildcardHost := "*"
	if host != "" {
		recordType = "CNAME"
		wildcardHost = "*." + host
	}

	existingRecs, err := dnsProvider.GetRecords(ctx, domain)
	if err != nil {
		return
	}

	deleteList := []libdns.Record{}
	for _, rec := range existingRecs {
		if rec.Type == "A" || rec.Type == "AAAA" || rec.Type == "CNAME" || rec.Type == "ANAME" {
			if rec.Name == host || rec.Name == wildcardHost {
				delRec := libdns.Record{
					ID:    rec.ID,
					Type:  rec.Type,
					Name:  rec.Name,
					Value: rec.Value,
				}
				deleteList = append(deleteList, delRec)
			}
		}
	}

	if len(deleteList) > 0 {
		_, err = dnsProvider.DeleteRecords(ctx, domain, deleteList)
		if err != nil {
			return
		}
	}

	_, err = dnsProvider.SetRecords(ctx, domain, []libdns.Record{
		libdns.Record{
			Type:  recordType,
			Name:  host,
			Value: targetDomain,
		},
		libdns.Record{
			Type:  "CNAME",
			Name:  wildcardHost,
			Value: targetDomain,
		},
	})
	if err != nil {
		return
	}

	return

}

func createCertCache() *certmagic.Cache {
	var certCache *certmagic.Cache
	// TODO: probably need to be calling certCache.Stop()
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			// TODO: this never seems to be called, but I'm worried it might introduce bugs in
			// the future by returning a different config than defined below.
			return certmagic.New(certCache, certmagic.Config{}), nil
		},
		Logger: zap.NewNop(),
	})

	return certCache
}

func createNormalCertConfig(certCache *certmagic.Cache, db *sql.DB, acmeEmail string) (certConfig *certmagic.Config, err error) {
	//certStorage := &certmagic.FileStorage{"./certs"}
	certStorage, err := NewCertmagicSqliteStorage(db)
	if err != nil {
		return
	}

	//acmeCA := certmagic.LetsEncryptStagingCA
	acmeCA := certmagic.LetsEncryptProductionCA

	certConfig = certmagic.New(certCache, certmagic.Config{
		Storage: certStorage,
		Logger:  zap.NewNop(),
	})

	issuer := certmagic.NewACMEIssuer(certConfig, certmagic.ACMEIssuer{
		CA:                   acmeCA,
		Email:                acmeEmail,
		Agreed:               true,
		DisableHTTPChallenge: true,
		Logger:               zap.NewNop(),
	})
	certConfig.Issuers = []certmagic.Issuer{issuer}

	return
}

func createDNSCertConfig(certCache *certmagic.Cache, db *sql.DB, acmeEmail string, dnsProvider DNSProvider) (certConfig *certmagic.Config, err error) {

	//certStorage := &certmagic.FileStorage{"./certs"}
	certStorage, err := NewCertmagicSqliteStorage(db)
	if err != nil {
		return
	}

	//acmeCA := certmagic.LetsEncryptStagingCA
	acmeCA := certmagic.LetsEncryptProductionCA

	certConfig = certmagic.New(certCache, certmagic.Config{
		Storage: certStorage,
		Logger:  zap.NewNop(),
	})

	acmeIssuer := certmagic.NewACMEIssuer(certConfig, certmagic.ACMEIssuer{
		CA:                   acmeCA,
		Email:                acmeEmail,
		Agreed:               true,
		DisableHTTPChallenge: true,
		Logger:               zap.NewNop(),
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: dnsProvider,
			},
		},
	})

	certConfig.Issuers = []certmagic.Issuer{acmeIssuer}

	return
}

func createOnDemandCertConfig(certCache *certmagic.Cache, db *sql.DB, acmeEmail string) (onDemandConfig *certmagic.Config, err error) {
	//certStorage := &certmagic.FileStorage{"./certs"}
	certStorage, err := NewCertmagicSqliteStorage(db)
	if err != nil {
		return
	}

	//acmeCA := certmagic.LetsEncryptStagingCA
	acmeCA := certmagic.LetsEncryptProductionCA

	onDemandConfig = certmagic.New(certCache, certmagic.Config{
		Storage: certStorage,
		Logger:  zap.NewNop(),
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				// TODO: verify domain is in tunnels
				//if name != tunnelDomain {
				//	return fmt.Errorf("not allowed")
				//}
				return nil
			},
		},
	})

	onDemandIssuer := certmagic.NewACMEIssuer(onDemandConfig, certmagic.ACMEIssuer{
		CA:                   acmeCA,
		Email:                acmeEmail,
		Agreed:               true,
		DisableHTTPChallenge: true,
		Logger:               zap.NewNop(),
	})
	onDemandConfig.Issuers = []certmagic.Issuer{onDemandIssuer}

	return
}

func getHost(r *http.Request, behindProxy bool) string {
	return r.Host
}

func checkDomains(db Database, certCache *certmagic.Cache) (err error) {

	acmeEmail, err := db.GetACMEEmail()
	if err != nil {
		return
	}

	certConfig, err := createNormalCertConfig(certCache, db.GetSQLDB(), acmeEmail)

	domains, err := db.GetDomains()

	if err != nil {
		return
	}

	for _, domain := range domains {
		// TODO: wildcard domains via DNS-01 challenge
		err = certConfig.ManageSync(context.Background(), []string{domain.Domain})
		if err != nil {
			domain.Status = DomainStatusPending
			db.SetDomain(domain)
		} else if domain.Status != DomainStatusReady {
			domain.Status = DomainStatusReady
			db.SetDomain(domain)
		}
	}

	return
}
