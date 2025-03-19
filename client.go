package waygate

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/anderspitman/treemess-go"
	"github.com/caddyserver/certmagic"
	"github.com/gemdrive/gemdrive-go"
	"github.com/lastlogin-net/obligator"
)

type TunnelType string

const TunnelTypeHTTPS = "HTTPS"
const TunnelTypeTLS = "TLS"
const TunnelTypeTCP = "TCP"
const TunnelTypeUDP = "UDP"

var WaygateServerDomain string = "waygate.io"

type ClientConfig struct {
	Users        []string
	ServerDomain string
	Token        string
	Dir          string
	Public       bool
	NoBrowser    bool
	DNSProvider  string
	DNSUser      string
	DNSToken     string
}

type Client struct {
	db         *ClientDatabase
	config     *ClientConfig
	eventCh    chan interface{}
	authServer *obligator.Server
	tmpl       *template.Template
}

func NewClient(config *ClientConfig) *Client {

	db, err := NewClientDatabase("waygate.sqlite")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	tmpl, err := template.ParseFS(fs, "templates/*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	configCopy := *config

	if configCopy.ServerDomain != "" && configCopy.ServerDomain != WaygateServerDomain {
		err := db.SetServerUri(configCopy.ServerDomain)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	dbServerUri, err := db.GetServerUri()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if dbServerUri != "" {
		WaygateServerDomain = configCopy.ServerDomain
	}

	dnsProvider, err := getDnsProvider(configCopy.DNSProvider, configCopy.DNSToken, configCopy.DNSUser)
	exitOnError(err)

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the waygate client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	certmagic.HTTPSPort, err = randomOpenPort()
	exitOnError(err)

	if len(configCopy.Users) > 0 {
		certmagic.DefaultACME.Email = configCopy.Users[0]
	}
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSProvider: dnsProvider,
	}

	domains, err := db.GetDomains()
	exitOnError(err)

	certConfig := certmagic.NewDefault()

	for _, domain := range domains {
		ctx := context.Background()
		err := certConfig.ManageAsync(ctx, []string{domain, "*." + domain})
		exitOnError(err)
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

	session, err := NewClientSession(token, c.db)
	if err != nil {
		return err
	}

	//listener, err := Listen("tls", "tn7.org", ListenOptions{
	listener, err := session.Listen("tls", "")
	if err != nil {
		return err
	}

	tunConfig := listener.GetTunnelConfig()

	dashUri := "https://dash." + tunConfig.Domain
	redirUriCh <- dashUri

	dbPrefix := "auth_"
	authDb, err := obligator.NewSqliteDatabaseWithDb(c.db.db.DB, dbPrefix)
	exitOnError(err)

	authDomain := "auth." + tunConfig.Domain
	authConfig := obligator.ServerConfig{
		Prefix:       "waygate_client_",
		Database:     authDb,
		DatabaseDir:  c.config.Dir,
		ApiSocketDir: c.config.Dir,
		//Domains: []string{
		//        authDomain,
		//},
		AuthDomains: []string{
			authDomain,
		},
		Users: c.config.Users,
		OAuth2Providers: []*obligator.OAuth2Provider{
			&obligator.OAuth2Provider{
				ID:            "lastlogin",
				Name:          "LastLogin",
				URI:           "https://lastlogin.io",
				ClientID:      "https://" + authDomain,
				OpenIDConnect: true,
			},
		},
	}
	authServer := obligator.NewServer(authConfig)
	c.authServer = authServer

	filesDomain := "files." + tunConfig.Domain

	gdDataDir := filepath.Join(c.config.Dir, "gemdrive")
	gdConfig := &gemdrive.Config{
		DashboardDomain: "dash." + filesDomain,
		FsDomain:        filesDomain,
		Dirs:            []string{filepath.Join(gdDataDir, "files")},
		DataDir:         gdDataDir,
	}

	tmess := treemess.NewTreeMess()
	gdTmess := tmess.Branch()

	gdServer, err := gemdrive.NewServer(gdConfig, gdTmess)
	if err != nil {
		return err
	}

	gdCh := make(chan treemess.Message)
	tmess.Listen(gdCh)

	//tmess.Send("start", nil)

	go func() {
		for msg := range gdCh {
			fmt.Println(msg)
		}
	}()

	mux := NewClientMux(authServer, gdServer, c.db)

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		tunnel, err := c.db.GetTunnel(r.Host)
		if err == nil {
			proxyHttp(w, r, httpClient, tunnel.ClientAddress, false)
			return
		}

		tunnels, err := c.db.GetTunnels()
		if err != nil {
			fmt.Println(err)
			return
		}

		domains, err := c.db.GetDomains()
		if err != nil {
			fmt.Println(err)
			return
		}

		tmplData := struct {
			Domains []string
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

	mux.HandleFunc("/add-tunnel", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		serverAddress := r.Form.Get("server_address")
		if serverAddress == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing server_address")
			return
		}

		clientAddress := r.Form.Get("client_address")
		if clientAddress == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing client_address")
			return
		}

		protected := r.Form.Get("protected") == "on"
		tlsPassthrough := r.Form.Get("tls_passthrough") == "on"
		tunnelType := r.Form.Get("type")

		if tunnelType != TunnelTypeHTTPS && tunnelType != TunnelTypeTLS && tunnelType != TunnelTypeTCP && tunnelType != TunnelTypeUDP {
			w.WriteHeader(400)
			io.WriteString(w, "Invalid 'type' parameter")
			return
		}

		//hostname := r.Form.Get("hostname")

		//subdomain := domain
		//if hostname != "" {
		//	subdomain = fmt.Sprintf("%s.%s", hostname, domain)
		//}

		tunnel := &ClientTunnel{
			ServerAddress:  serverAddress,
			ClientAddress:  clientAddress,
			Protected:      protected,
			Type:           tunnelType,
			TLSPassthrough: tlsPassthrough,
		}

		err := c.db.SetTunnel(tunnel)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = openTunnel(session, mux, tunnel)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
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

		err := c.db.SetDomain(domain)
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
			err = openTunnel(session, mux, tunnel)
			exitOnError(err)
		}()
	}

	go func() {
		err := http.Serve(listener, mux)
		if err != nil {
			fmt.Println("listener done", err)
		}
	}()

	users, err := c.authServer.GetUsers()
	if err != nil {
		return err
	}

	if c.eventCh != nil {
		c.eventCh <- TunnelConnectedEvent{
			TunnelConfig: tunConfig,
		}

		c.eventCh <- UsersUpdatedEvent{
			Users: users,
		}
	}

	return nil
}

func (c *Client) SetTunnel(tunnel *ClientTunnel) error {
	return c.db.SetTunnel(tunnel)
}

func (c *Client) GetUsers() ([]*obligator.User, error) {
	if c.authServer == nil {
		return nil, errors.New("No auth server")
	}

	return c.authServer.GetUsers()
}

func (c *Client) AddUser(user obligator.User) error {
	if c.authServer == nil {
		return errors.New("No auth server")
	}

	err := c.authServer.AddUser(user)
	if err != nil {
		return err
	}

	users, err := c.authServer.GetUsers()
	if err != nil {
		return err
	}

	if c.eventCh != nil {
		c.eventCh <- UsersUpdatedEvent{
			Users: users,
		}
	}

	return nil
}

type UsersUpdatedEvent struct {
	Users []*obligator.User
}

type TunnelConnectedEvent struct {
	TunnelConfig TunnelConfig
}

type OAuth2AuthUriEvent struct {
	Uri string
}

type ClientMux struct {
	db         *ClientDatabase
	mux        *http.ServeMux
	authServer *obligator.Server
	fileServer *gemdrive.Server
}

func NewClientMux(authServer *obligator.Server, fileServer *gemdrive.Server, db *ClientDatabase) *ClientMux {
	m := &ClientMux{
		db:         db,
		mux:        http.NewServeMux(),
		authServer: authServer,
		fileServer: fileServer,
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

	authDomain := m.authServer.AuthDomains()[0]

	if host == m.fileServer.FsDomain() {
		m.fileServer.ServeHTTP(w, r)
		return
	} else if host != authDomain {

		tunnel, err := m.db.GetTunnel(host)
		if err == nil && !tunnel.Protected {
			m.mux.ServeHTTP(w, r)
			return
		}

		validation, err := m.authServer.Validate(r)
		if err != nil {

			redirectUri := fmt.Sprintf("https://%s%s", host, r.URL.Path)

			authRedirUri := fmt.Sprintf("https://%s/auth", authDomain)

			authUri := obligator.AuthUri(authRedirUri, &obligator.OAuth2AuthRequest{
				// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
				ResponseType: "none",
				ClientId:     "https://" + host,
				RedirectUri:  redirectUri,
				State:        "",
				Scope:        "",
			})

			http.Redirect(w, r, authUri, 303)
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
			r.Header.Set("UserIDType", validation.IdType)
			r.Header.Set("UserID", validation.Id)
		}

		if host == m.fileServer.DashboardDomain() {
			m.fileServer.ServeHTTP(w, r)
			return
		}
	} else {
		m.authServer.ServeHTTP(w, r)
		return
	}

	m.mux.ServeHTTP(w, r)
}

func openTunnel(session *ClientSession, mux *ClientMux, tunnel *ClientTunnel) error {

	addr := tunnel.ServerAddress

	switch tunnel.Type {
	case TunnelTypeUDP:
		go proxyUdp(session, tunnel)

	case TunnelTypeTCP:
		fmt.Println("listen tcp")
		// TODO: this should probably be called in a goroutine
		listener, err := session.Listen("tcp", addr)
		if err != nil {
			return err
		}

		go proxyTcpConns(listener, tunnel)
	case TunnelTypeTLS:
		fallthrough
	case TunnelTypeHTTPS:
		fmt.Println("listen tls")

		if tunnel.TLSPassthrough {
			// TODO: this should probably be called in a goroutine
			listener, err := session.Listen("tcp", addr)
			if err != nil {
				return err
			}

			go proxyTcpConns(listener, tunnel)
		} else {
			listener, err := session.Listen("tls", addr)
			if err != nil {
				return err
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

	return nil
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
