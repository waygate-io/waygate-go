package waygate

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/anderspitman/treemess-go"
	"github.com/gemdrive/gemdrive-go"
	"github.com/lastlogin-net/obligator"
)

var WaygateServerDomain string = "waygate.io"

type ClientConfig struct {
	Users        []string
	ServerDomain string
	Token        string
	Dir          string
	Public       bool
	NoBrowser    bool
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

	listener, err := ListenWithOpts("tcp", "", token, c.db)
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

		forward, err := c.db.GetForward(r.Host)
		if err == nil {
			proxyHttp(w, r, httpClient, forward.TargetAddress, false)
			return
		}

		forwards, err := c.db.GetForwards()
		if err != nil {
			fmt.Println(err)
			return
		}

		tmplData := struct {
			Domains  []string
			Forwards []*Forward
		}{
			Domains:  []string{tunConfig.Domain},
			Forwards: forwards,
		}

		err = c.tmpl.ExecuteTemplate(w, "client.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

	})

	mux.HandleFunc("/add-forward", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		domain := r.Form.Get("domain")
		if domain == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing domain")
			return
		}

		targetAddr := r.Form.Get("target-address")
		if targetAddr == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing target-address")
			return
		}

		protected := r.Form.Get("protected") == "on"
		fmt.Println(r.Form.Get("protected"))

		hostname := r.Form.Get("hostname")

		subdomain := domain
		if hostname != "" {
			subdomain = fmt.Sprintf("%s.%s", hostname, domain)
		}

		err := c.db.SetForward(&Forward{
			Domain:        subdomain,
			TargetAddress: targetAddr,
			Protected:     protected,
		})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, "/", 303)
	})

	mux.HandleFunc("/delete-forward", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		domain := r.Form.Get("domain")
		if domain == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing domain")
			return
		}

		err := c.db.DeleteForwardByDomain(domain)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		http.Redirect(w, r, "/", 303)
	})

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

func (c *Client) SetForward(forward *Forward) error {
	return c.db.SetForward(forward)
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

		forward, err := m.db.GetForward(host)
		if err == nil && !forward.Protected {
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
