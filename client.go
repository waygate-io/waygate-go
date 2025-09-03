package waygate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
	//"github.com/anderspitman/treemess-go"
	"github.com/caddyserver/certmagic"
	//"github.com/gemdrive/gemdrive-go"
	"github.com/lastlogin-net/decent-auth-go"
	"github.com/takingnames/namedrop-go"
	namedropdns "github.com/takingnames/namedrop-libdns"
)

type TunnelType string

const TunnelTypeHTTPS = "HTTPS"
const TunnelTypeTLS = "TLS"
const TunnelTypeTCP = "TCP"
const TunnelTypeUDP = "UDP"

const authPrefix = "/waygate-auth"

var WaygateServerDomain string = "wg8.org"

type ClientConfig struct {
	Users           []string
	ServerURI       string
	Token           string
	Dir             string
	Public          bool
	NoBrowser       bool
	DNSProvider     string
	DNSUser         string
	DNSToken        string
	ACMEEmail       string
	ClientName      string
	TerminationType TerminationType
}

type Client struct {
	db          *ClientDatabase
	config      *ClientConfig
	eventCh     chan interface{}
	tmpl        *template.Template
	dnsProvider DNSProvider
	certConfig  *certmagic.Config
	certCache   *certmagic.Cache
	acmeEmail   string
	session     *ClientSession
	tunMux      *ClientMux
	authHandler *decentauth.Handler
}

func NewClient(config *ClientConfig) *Client {

	db, err := NewClientDatabase("waygate_client_db.sqlite3")
	exitOnError(err)

	tmpl, err := template.ParseFS(fs, "templates/*")
	exitOnError(err)

	configCopy := *config

	if configCopy.ServerURI != "" && configCopy.ServerURI != WaygateServerDomain {
		err := db.SetServerUri(configCopy.ServerURI)
		exitOnError(err)
	}

	dbServerUri, err := db.GetServerUri()
	exitOnError(err)

	if config.ClientName != "" {
		err := db.SetClientName(config.ClientName)
		exitOnError(err)
	}

	clientName, err := db.GetClientName()
	exitOnError(err)

	if clientName == "" {
		clientName, err = os.Hostname()
		exitOnError(err)

		err := db.SetClientName(clientName)
		exitOnError(err)
	}

	if dbServerUri != "" {
		WaygateServerDomain = configCopy.ServerURI
	}

	return &Client{
		db:      db,
		config:  &configCopy,
		eventCh: nil,
		tmpl:    tmpl,
	}
}

func (c *Client) ListenEvents(eventCh chan interface{}) {
	c.eventCh = eventCh
}

func (c *Client) Proxy(domain, addr string) {
	if domain == "" || addr == "" {
		return
	}

	//c.forwardMap[domain] = addr
	//printJson(c.forwardMap)
}

func (c *Client) Run() error {

	var err error
	configCopy := c.config
	db := c.db

	c.acmeEmail, err = db.GetACMEEmail()
	exitOnError(err)

	if configCopy.ACMEEmail != "" {
		c.acmeEmail = configCopy.ACMEEmail
		err = db.SetACMEEmail(c.acmeEmail)
		exitOnError(err)
	}

	for {
		if c.acmeEmail == "" {
			c.acmeEmail = prompt("Enter an email address for your Let's Encrypt account:\n")
			err = db.SetACMEEmail(c.acmeEmail)
			exitOnError(err)
		} else {
			break
		}
	}

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the waygate client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	certmagic.HTTPSPort, err = randomOpenPort()
	exitOnError(err)

	for _, userID := range configCopy.Users {
		err := db.SetUser(user{
			ID: userID,
		})
		exitOnError(err)
	}

	users, err := db.GetUsers()
	exitOnError(err)

	for len(users) < 1 {
		userID := prompt("No users configured. Enter a userID:\n")
		err := db.SetUser(user{
			ID: userID,
		})
		exitOnError(err)

		users, err = db.GetUsers()
		exitOnError(err)
	}

	c.certCache = createCertCache()

	// TODO: might be able to remove in favor of a more robust background
	// cert system
	if configCopy.DNSProvider != "" {

		c.dnsProvider, err = getDnsProvider(configCopy.DNSProvider, configCopy.DNSToken, configCopy.DNSUser)
		exitOnError(err)

		certConfig, err := createDNSCertConfig(c.certCache, db.db.DB, c.acmeEmail, c.dnsProvider)
		exitOnError(err)

		tunnels, err := db.GetTunnels()
		exitOnError(err)

		ctx := context.Background()
		for _, tun := range tunnels {
			if tun.Type == TunnelTypeHTTPS || tun.Type == TunnelTypeTLS {
				err := certConfig.ManageAsync(ctx, []string{tun.ServerAddress, "*." + tun.ServerAddress})
				exitOnError(err)
			}
		}
	}

	onDemandConfig, err := createOnDemandCertConfig(c.certCache, db.db.DB, "")
	exitOnError(err)

	token := c.config.Token
	redirUriCh := make(chan string)

	if token == "" {
		var err error
		token, err = c.db.GetToken()
		if err != nil {
			return err
		}
	}

	if (token == "" && !c.config.Public) || os.Getenv("WAYGATE_DEBUG_TOKEN") == "reset" {

		var err error

		if c.config.NoBrowser {

			token, err = DoDeviceFlow()
			if err != nil {
				return err
			}

			go func() {
				<-redirUriCh
			}()

		} else {
			tokenFlow, err := NewTokenFlow()
			if err != nil {
				return err
			}

			if c.eventCh != nil {
				c.eventCh <- OAuth2AuthUriEvent{
					Uri: tokenFlow.GetAuthUri(),
				}
			}

			token, err = tokenFlow.GetTokenWithRedirect(redirUriCh)
			if err != nil {
				return err
			}

		}

		err = c.db.SetToken(token)
		if err != nil {
			return err
		}
	} else {
		go func() {
			<-redirUriCh
		}()
	}

	if os.Getenv("WAYGATE_DEBUG_TOKEN") == "reset" {
		fmt.Println(token)
	}

	c.certConfig, err = createNormalCertConfig(c.certCache, c.db.db.DB, c.acmeEmail)
	exitOnError(err)

	//disableOnDemand := true
	disableOnDemand := false
	if disableOnDemand {
		if c.dnsProvider != nil {
			c.certConfig, err = createDNSCertConfig(c.certCache, c.db.db.DB, c.acmeEmail, c.dnsProvider)
			if err != nil {
				return err
			}
		} else {
			exitOnError(errors.New("Can't use disableOnDemand without DNS settings"))
		}
	}

	c.session, err = NewClientSession(token, c.db, onDemandConfig, c.config.TerminationType)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		// TODO: hacky to do this here
		os.Exit(64)
		return err
	}

	go func() {
		code := <-c.session.DoneChan
		if c.eventCh != nil {
			c.eventCh <- ErrorEvent{
				Code: code,
			}
		}
	}()

	//listener, err := Listen("tls", "tn7.org", ListenOptions{
	listener, err := c.session.Listen("tls", "")
	if err != nil {
		return err
	}

	tunConfig := listener.GetTunnelConfig()

	dashUri := "https://" + tunConfig.Domain

	if tunConfig.TerminationType == TerminationTypeClient {
		ctx := context.Background()
		err = c.certConfig.ManageAsync(ctx, []string{tunConfig.Domain})
		exitOnError(err)
	}

	redirUriCh <- dashUri

	kvStore, err := decentauth.NewSqliteKvStore(&decentauth.SqliteKvOptions{
		Db:        db.db.DB,
		TableName: "auth_kv",
	})
	exitOnError(err)

	adminID := users[len(users)-1].ID

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		KvStore: kvStore,
		Config: decentauth.Config{
			PathPrefix:  authPrefix,
			AdminID:     adminID,
			BehindProxy: false,
			LoginMethods: []decentauth.LoginMethod{
				decentauth.LoginMethod{
					Name: "LastLogin",
					URI:  "https://lastlogin.net",
					Type: decentauth.LoginMethodOIDC,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodAdminCode,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodQRCode,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodATProto,
				},
				decentauth.LoginMethod{
					Type: decentauth.LoginMethodFediverse,
				},
			},
		},
	})
	exitOnError(err)

	c.authHandler = authHandler

	// TODO: consider re-enabling GemDrive
	//filesDomain := "files." + tunConfig.Domain

	//gdDataDir := filepath.Join(c.config.Dir, "gemdrive")
	//gdConfig := &gemdrive.Config{
	//	DashboardDomain: "dash." + filesDomain,
	//	FsDomain:        filesDomain,
	//	Dirs:            []string{filepath.Join(gdDataDir, "files")},
	//	DataDir:         gdDataDir,
	//}

	//tmess := treemess.NewTreeMess()
	//gdTmess := tmess.Branch()

	//gdServer, err := gemdrive.NewServer(gdConfig, gdTmess)
	//if err != nil {
	//	return err
	//}

	//gdCh := make(chan treemess.Message)
	//tmess.Listen(gdCh)

	////tmess.Send("start", nil)

	//go func() {
	//	for msg := range gdCh {
	//		fmt.Println(msg)
	//	}
	//}()

	mux := NewClientMux(authHandler /*gdServer,*/, c.db, adminID)
	c.tunMux = NewClientMux(authHandler, c.db, adminID)

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	c.tunMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		tunnel, err := c.db.GetTunnel(r.Host)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		// TODO: feels like a hacky safety check
		if strings.HasPrefix(r.URL.Path, authPrefix) {
			authHandler.ServeHTTP(w, r)
			return
		}

		proxyHttp(w, r, httpClient, tunnel.ClientAddress, false)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if strings.HasPrefix(r.URL.Path, authPrefix) {
			authHandler.ServeHTTP(w, r)
			return
		}

		tunnels, err := c.db.GetTunnels()
		if err != nil {
			fmt.Println(err)
			return
		}

		//var domains []string
		//if c.dnsProvider != nil {
		//	zones, err := c.dnsProvider.ListZones(r.Context())
		//	if err != nil {
		//		fmt.Println(err)
		//		return
		//	}

		//	for _, zone := range zones {
		//		domains = append(domains, zone.Name)
		//	}
		//}

		domains, err := c.db.GetDomains()
		if err != nil {
			fmt.Println(err)
			return
		}

		tmplData := struct {
			Domains []Domain
			Tunnels []*ClientTunnel
		}{
			Domains: domains,
			Tunnels: tunnels,
		}

		err = c.tmpl.ExecuteTemplate(w, "client.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

	})

	// TODO: handle concurrent requests
	var flowState *oauth.AuthCodeFlowState
	var providerUri string
	flowStateMut := &sync.Mutex{}

	httpServer := &http.Server{
		Handler: mux,
	}

	exitReason := "normal"

	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		exitReason = "shutdown"
		exit(w, r, c.tmpl, httpServer)
	})

	mux.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		exitReason = "restart"
		exit(w, r, c.tmpl, httpServer)
	})

	mux.HandleFunc("/add-domain-takingnames", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		puri := "https://takingnames.io/namedrop"
		puriParam := r.Form.Get("namedrop_provider_uri")
		if puriParam != "" {
			puri = puriParam
		}

		clientId := "https://" + r.Host
		redirUri := fmt.Sprintf("%s/add-domain-takingnames/callback", clientId)
		authReq := &oauth.AuthRequest{
			ClientId:    clientId,
			RedirectUri: redirUri,
			Scopes:      []string{namedrop.ScopeHosts, namedrop.ScopeAcme},
		}

		authUri := puri + "/authorize"
		fs, err := oauth.StartAuthCodeFlow(authUri, authReq)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		flowStateMut.Lock()
		flowState = fs
		providerUri = puri
		flowStateMut.Unlock()

		http.Redirect(w, r, flowState.AuthUri, 303)
	})

	mux.HandleFunc("/add-domain-takingnames/callback", func(w http.ResponseWriter, r *http.Request) {
		flowStateMut.Lock()
		fs := flowState
		puri := providerUri
		flowState = nil
		providerUri = ""
		flowStateMut.Unlock()

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		tokenUri := puri + "/token"
		resBytes, err := oauth.CompleteAuthCodeFlow(tokenUri, code, state, fs)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		var tokenRes *namedrop.TokenResponse

		err = json.Unmarshal(resBytes, &tokenRes)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		dnsProvider := &namedropdns.Provider{
			ServerUri: puri,
			TokenData: tokenRes,
		}

		// TODO: hacky. we probably shouldn't completely override DNS
		// config passed in by user
		c.dnsProvider = dnsProvider

		host := tokenRes.Permissions[0].Host
		domain := tokenRes.Permissions[0].Domain

		behindProxy := false
		curHost := getHost(r, behindProxy)

		err = pointDomainAtDomain(r.Context(), c.dnsProvider, host, domain, curHost)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		fqdn := domain
		if host != "" {
			fqdn = fmt.Sprintf("%s.%s", host, domain)
		}

		c.certConfig, err = createDNSCertConfig(c.certCache, c.db.db.DB, c.acmeEmail, c.dnsProvider)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		ctx := context.Background()
		err = c.certConfig.ManageAsync(ctx, []string{fqdn, "*." + fqdn})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = db.SetDomain(Domain{
			Domain: fqdn,
			Status: DomainStatusPending,
		})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, "/", 303)
	})

	mux.HandleFunc("/add-tunnel", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		err := c.AddTunnel(r.Context(), r.Form)

		if httpErr, ok := err.(*httpError); ok {
			w.WriteHeader(httpErr.statusCode)
			io.WriteString(w, httpErr.message)
			return
		} else if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, "/add-tunnel error")
			return
		}

		http.Redirect(w, r, "/", 303)
	})

	mux.HandleFunc("/delete-tunnel", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		tunnelType := TunnelType(r.Form.Get("type"))
		if tunnelType == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing type")
			return
		}

		address := r.Form.Get("address")
		if address == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing address")
			return
		}

		err := c.db.DeleteTunnel(tunnelType, address)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, "/", 303)
	})

	mux.HandleFunc("/add-domain", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		domain := r.Form.Get("domain")
		if domain == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing domain")
			return
		}

		err := c.db.SetDomain(Domain{
			Domain: domain,
			Status: DomainStatusPending,
		})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		certConfig := certmagic.NewDefault()
		ctx := context.Background()
		err = certConfig.ManageSync(ctx, []string{domain, "*." + domain})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, "/", 303)
	})

	mux.HandleFunc("/delete-domain", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		domain := r.Form.Get("domain")
		if domain == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing domain")
			return
		}

		err := c.db.DeleteDomain(domain)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, "/", 303)
	})

	tunnels, err := c.db.GetTunnels()
	if err != nil {
		return err
	}

	for _, tunnel := range tunnels {
		printJson(tunnel)
		go func() {
			_, err = openTunnel(c.session, c.tunMux, tunnel)
			exitOnError(err)
		}()
	}

	// TODO: probably need to re-enable at some point
	//go func() {
	//	for {
	//		err := checkDomains(db, c.certCache)
	//		if err != nil {
	//			fmt.Fprintf(os.Stderr, err.Error())
	//		}
	//		time.Sleep(5 * time.Second)
	//	}
	//}()

	go func() {
		err = httpServer.Serve(listener)
		if err != nil {
			fmt.Println("listener done", err)
		}

		switch exitReason {
		case "restart":
			if c.eventCh != nil {
				c.eventCh <- ErrorEvent{
					Code: 64,
				}
			}
		case "shutdown":
			if c.eventCh != nil {
				c.eventCh <- ErrorEvent{
					Code: 0,
				}
			}
		default:
			if c.eventCh != nil {
				c.eventCh <- ErrorEvent{
					Code: 0,
				}
			}
		}
	}()

	if c.eventCh != nil {
		c.eventCh <- TunnelConnectedEvent{
			TunnelConfig: tunConfig,
		}
	}

	go func() {
		httpClient := http.Client{
			Timeout: 5 * time.Second,
		}
		for {
			time.Sleep(30 * time.Second)

			res, err := httpClient.Get(dashUri + "/check")
			if err != nil {
				if c.eventCh != nil {
					c.eventCh <- ErrorEvent{
						Code: 64,
					}
				}
			}

			if res.StatusCode != 200 {
				if c.eventCh != nil {
					c.eventCh <- ErrorEvent{
						Code: 65,
					}
				}
			}
		}
	}()

	return nil
}

func (c *Client) GetTunnels() ([]*ClientTunnel, error) {
	return c.db.GetTunnels()
}

func (c *Client) DeleteTunnel(tunType TunnelType, addr string) error {
	return c.db.DeleteTunnel(tunType, addr)
}

func (c *Client) GetDomains() ([]Domain, error) {
	return c.db.GetDomains()
}

func (c *Client) DeleteDomain(domain string) error {
	return c.db.DeleteDomain(domain)
}

func (c *Client) AddTunnel(ctx context.Context, params url.Values) error {

	clientAddressArg := params.Get("client_address")
	if clientAddressArg == "" {
		return newHTTPError(400, "Missing client_address")
	}

	clientPort := params.Get("client_port")
	if clientPort == "" {
		return newHTTPError(400, "Missing client_port")
	}

	clientAddress := fmt.Sprintf("%s:%s", clientAddressArg, clientPort)

	protected := params.Get("protected") == "on"
	tlsPassthrough := params.Get("tls_passthrough") == "on"
	tunnelType := TunnelType(params.Get("type"))

	if tunnelType != TunnelTypeHTTPS && tunnelType != TunnelTypeTLS && tunnelType != TunnelTypeTCP && tunnelType != TunnelTypeUDP {
		return newHTTPError(400, "Invalid 'type' parameter")
	}

	var serverAddress string
	var tunDomain string
	var tunHost string
	if tunnelType == TunnelTypeHTTPS || tunnelType == TunnelTypeTLS {

		tunDomain = params.Get("domain")
		if tunDomain == "" {
			return newHTTPError(400, "Missing domain param")
		}

		fqdn := tunDomain

		tunHost = params.Get("host")
		if tunHost != "" {
			fqdn = fmt.Sprintf("%s.%s", tunHost, tunDomain)
		}

		if c.dnsProvider != nil {
			var err error
			c.certConfig, err = createDNSCertConfig(c.certCache, c.db.db.DB, c.acmeEmail, c.dnsProvider)
			if err != nil {
				return newHTTPError(500, err.Error())
			}
			err = c.certConfig.ManageAsync(context.Background(), []string{fqdn, "*." + fqdn})
			if err != nil {
				return newHTTPError(500, err.Error())
			}
		}

		serverAddress = fqdn
	} else {
		serverPort := params.Get("server_port")
		if serverPort == "" {
			return newHTTPError(400, "Missing server_port")
		}

		serverAddress = fmt.Sprintf("0.0.0.0:%s", serverPort)
	}

	tunnel := &ClientTunnel{
		ServerAddress:  serverAddress,
		ClientAddress:  clientAddress,
		Protected:      protected,
		Type:           tunnelType,
		TLSPassthrough: tlsPassthrough,
	}

	err := c.db.SetTunnel(tunnel)
	if err != nil {
		return newHTTPError(500, err.Error())
	}

	serverTunnelDomain, err := openTunnel(c.session, c.tunMux, tunnel)
	if err != nil {
		return newHTTPError(500, err.Error())
	}

	if serverTunnelDomain != "" && c.dnsProvider != nil {
		err := pointDomainAtDomain(ctx, c.dnsProvider, tunHost, tunDomain, serverTunnelDomain)
		if err != nil {
			return newHTTPError(500, err.Error())
		}
	}

	return nil
}

func (c *Client) SetTunnel(tunnel *ClientTunnel) error {
	return c.db.SetTunnel(tunnel)
}

func (c *Client) CreateSession(id string) (code string, err error) {
	res, err := c.authHandler.CreateSession(decentauth.CreateSessionRequest{
		Id:     id,
		IdType: decentauth.IDTypeEmail,
	})

	if err != nil {
		return
	}

	code = res.Code

	return
}

//type UsersUpdatedEvent struct {
//	Users []*obligator.User
//}

type TunnelConnectedEvent struct {
	TunnelConfig TunnelConfig
}

type OAuth2AuthUriEvent struct {
	Uri string
}

type ErrorEvent struct {
	Code int
}

type ClientMux struct {
	db          *ClientDatabase
	mux         *http.ServeMux
	authHandler *decentauth.Handler
	adminID     string
	//fileServer *gemdrive.Server
}

func NewClientMux(authHandler *decentauth.Handler /*fileServer *gemdrive.Server,*/, db *ClientDatabase, adminID string) *ClientMux {
	m := &ClientMux{
		db:          db,
		mux:         http.NewServeMux(),
		authHandler: authHandler,
		adminID:     adminID,
		//fileServer: fileServer,
	}
	return m
}

func (s *ClientMux) Handle(p string, h http.Handler) {
	s.mux.Handle(p, h)
}

func (s *ClientMux) HandleFunc(p string, f func(w http.ResponseWriter, r *http.Request)) {
	s.mux.HandleFunc(p, f)
}

func (m *ClientMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; script-src 'none'")
	//w.Header().Set("Referrer-Policy", "no-referrer")

	host := r.Host

	//if host == m.fileServer.FsDomain() {
	//	m.fileServer.ServeHTTP(w, r)
	//	return
	//} else if host != authDomain {

	if !strings.HasPrefix(r.URL.Path, authPrefix) {

		if r.URL.Path == "/check" {
			return
		}

		tunnel, err := m.db.GetTunnel(host)
		if err == nil && !tunnel.Protected {
			m.mux.ServeHTTP(w, r)
			return
		}

		session := m.authHandler.GetSession(r)
		if session == nil {
			http.Redirect(w, r, authPrefix, 303)
			return
		} else if session.Id != m.adminID {
			http.Redirect(w, r, authPrefix+"/logout", 303)
			return
		}

		// TODO: strip auth cookies before sending upstream

		originHeader := r.Header.Get("Origin")
		origin := ""

		if originHeader != "" {
			originUrl, err := url.Parse(originHeader)
			if err != nil {
				w.WriteHeader(500)
				return
			}

			origin = originUrl.Host
		}

		if origin == "" || origin == r.Host {
			// TODO: according to the docs we're not supposed to be
			// modifying r: https://pkg.go.dev/net/http#Handler
			r.Header.Set("UserIDType", session.IdType)
			r.Header.Set("UserID", session.Id)
		}

		//if host == m.fileServer.DashboardDomain() {
		//	m.fileServer.ServeHTTP(w, r)
		//	return
		//}
	}

	m.mux.ServeHTTP(w, r)
}

func openTunnel(session *ClientSession, mux *ClientMux, tunnel *ClientTunnel) (domain string, err error) {

	addr := tunnel.ServerAddress
	var listener *Listener

	switch tunnel.Type {
	case TunnelTypeUDP:
		go proxyUdp(session, tunnel)

	case TunnelTypeTCP:
		fmt.Println("listen tcp")
		// TODO: this should probably be called in a goroutine
		listener, err = session.Listen("tcp", addr)
		if err != nil {
			return
		}

		go proxyTcpConns(listener, tunnel)
	case TunnelTypeTLS:
		fmt.Println("listen tls")

		// TODO: this should probably be called in a goroutine
		listener, err = session.Listen("tls", addr)
		if err != nil {
			return
		}

		go proxyTcpConns(listener, tunnel)

	case TunnelTypeHTTPS:
		fmt.Println("listen https")

		if tunnel.TLSPassthrough {
			// TODO: this should probably be called in a goroutine
			listener, err = session.Listen("tcp", addr)
			if err != nil {
				return
			}

			go proxyTcpConns(listener, tunnel)
		} else {
			listener, err = session.Listen("tls", addr)
			if err != nil {
				return
			}

			// TODO: This feels hacky. see if we can avoid spinning up a
			// new HTTP server for each client
			go func() {
				err := http.Serve(listener, mux)
				if err != nil {
					fmt.Println("listener done", err)
				}
			}()
		}
	}

	if listener != nil {
		tunConfig := listener.GetTunnelConfig()
		domain = tunConfig.Domain
	}

	return
}

func proxyTcpConns(listener net.Listener, tunnel *ClientTunnel) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			break
		}

		go proxyTcp(conn, tunnel.ClientAddress)
	}
}

func proxyTcp(downstreamConn net.Conn, upstreamAddr string) {
	upstreamConn, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	cwConn := downstreamConn.(connCloseWriter)
	cwUpstreamConn := upstreamConn.(connCloseWriter)

	ConnectConns(cwConn, cwUpstreamConn)
}

func proxyUdp(session *ClientSession, tunnel *ClientTunnel) {

	downstreamAddr := tunnel.ServerAddress

	udpAddr, err := net.ResolveUDPAddr("udp", downstreamAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	downstreamConn, err := session.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	upstreamUDPAddr, err := net.ResolveUDPAddr("udp", tunnel.ClientAddress)
	if err != nil {
		fmt.Println(err)
		return
	}

	upbuf := make([]byte, 64*1024)
	downbuf := make([]byte, 64*1024)

	connMap := make(map[string]*net.UDPConn)
	mut := &sync.Mutex{}

	go func() {
		for {
			n, srcAddr, err := downstreamConn.ReadFromUDP(upbuf)
			if err != nil {
				fmt.Println(err)
				return
			}

			mut.Lock()
			upstreamConn, exists := connMap[srcAddr.String()]
			mut.Unlock()

			if !exists {
				upstreamConn, err = net.DialUDP("udp", nil, upstreamUDPAddr)
				if err != nil {
					fmt.Println(err)
					return
				}

				mut.Lock()
				connMap[srcAddr.String()] = upstreamConn
				mut.Unlock()

				// TODO: clean up this nesting
				go func() {

					srcUDPAddr, err := net.ResolveUDPAddr("udp", srcAddr.String())
					if err != nil {
						fmt.Println(err)
						return
					}

					for {
						n, _, err := upstreamConn.ReadFromUDP(downbuf)
						if err != nil {
							fmt.Println(err)
							return
						}

						_, err = downstreamConn.WriteToUDP(downbuf[:n], srcUDPAddr)
						if err != nil {
							fmt.Println(err)
							return
						}
					}
				}()
			}

			_, err = upstreamConn.Write(upbuf[:n])
			if err != nil {
				fmt.Println(err)
				return
			}
		}
	}()
}
