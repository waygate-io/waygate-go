package waygate

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/anderspitman/treemess-go"
	"github.com/gemdrive/gemdrive-go"
	"github.com/lastlogin-io/obligator"
)

var WaygateServerDomain string = "waygate.io"

type ClientConfig struct {
	Users        []string
	ServerDomain string
	Token        string
	Dir          string
}

type Client struct {
	config     *ClientConfig
	eventCh    chan interface{}
	forwardMan *ForwardManager
	authServer *obligator.Server
	tmpl       *template.Template
}

func NewClient(config *ClientConfig) *Client {

	tmpl, err := template.ParseFS(fs, "templates/*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	configCopy := *config

	if configCopy.ServerDomain != "" {
		WaygateServerDomain = configCopy.ServerDomain
	}

	return &Client{
		config:     &configCopy,
		eventCh:    nil,
		forwardMan: NewForwardManager(),
		tmpl:       tmpl,
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

	certDir := filepath.Join(c.config.Dir, "certs")

	listener, err := Listen("tcp", "", token, certDir)
	if err != nil {
		return err
	}

	tunConfig := listener.GetTunnelConfig()

	dashUri := "https://dash." + tunConfig.Domain
	redirUriCh <- dashUri

	authDomain := "auth." + tunConfig.Domain
	authConfig := obligator.ServerConfig{
		RootUri:      "https://" + authDomain,
		Prefix:       "waygate_client_auth_",
		StorageDir:   c.config.Dir,
		DatabaseDir:  c.config.Dir,
		ApiSocketDir: c.config.Dir,
	}
	authServer := obligator.NewServer(authConfig)
	c.authServer = authServer
	err = authServer.SetOAuth2Provider(obligator.OAuth2Provider{
		ID:            "lastlogin",
		Name:          "LastLogin",
		URI:           "https://lastlogin.io",
		ClientID:      "https://" + authDomain,
		OpenIDConnect: true,
	})
	if err != nil {
		panic(err)
	}

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
		panic(err)
	}

	gdCh := make(chan treemess.Message)
	tmess.Listen(gdCh)

	//tmess.Send("start", nil)

	go func() {
		for msg := range gdCh {
			fmt.Println(msg)
		}
	}()

	mux := NewClientMux(authServer, gdServer, c.forwardMan)

	httpClient := &http.Client{
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		forward, exists := c.forwardMan.Get(r.Host)
		if exists {
			proxyHttp(w, r, httpClient, forward.TargetAddress, false)
			return
		}

		tmplData := struct {
			Domains  []string
			Forwards map[string]*Forward
		}{
			Domains:  []string{tunConfig.Domain},
			Forwards: c.forwardMan.GetAll(),
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
		printJson(r.Form)

		hostname := r.Form.Get("hostname")
		if hostname == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing hostname")
			return
		}

		domain := r.Form.Get("domain")
		if hostname == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing domain")
			return
		}

		targetAddr := r.Form.Get("target-address")
		if hostname == "" {
			w.WriteHeader(400)
			io.WriteString(w, "Missing target-address")
			return
		}

		protected := r.Form.Get("protected") == "on"
		fmt.Println(r.Form.Get("protected"))

		subdomain := fmt.Sprintf("%s.%s", hostname, domain)

		c.forwardMan.Set(subdomain, &Forward{
			TargetAddress: targetAddr,
			Protected:     protected,
		})

		http.Redirect(w, r, "/", 303)
	})

	go http.Serve(listener, mux)

	users, err := c.authServer.GetUsers()
	if err != nil {
		panic(err)
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

func (c *Client) GetUsers() ([]obligator.User, error) {
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
	Users []obligator.User
}

type TunnelConnectedEvent struct {
	TunnelConfig TunnelConfig
}

type OAuth2AuthUriEvent struct {
	Uri string
}

type ClientMux struct {
	mux        *http.ServeMux
	authServer *obligator.Server
	fileServer *gemdrive.Server
	forwardMan *ForwardManager
}

func NewClientMux(authServer *obligator.Server, fileServer *gemdrive.Server, forwardMan *ForwardManager) *ClientMux {
	m := &ClientMux{
		mux:        http.NewServeMux(),
		authServer: authServer,
		fileServer: fileServer,
		forwardMan: forwardMan,
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

		forward, exists := m.forwardMan.Get(host)
		if exists && !forward.Protected {
			m.mux.ServeHTTP(w, r)
			return
		}

		_, err := m.authServer.Validate(r)
		if err != nil {

			redirectUri := fmt.Sprintf("https://%s%s", host, r.URL.Path)

			authUri := m.authServer.AuthUri(&obligator.OAuth2AuthRequest{
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

type Forward struct {
	Protected     bool
	TargetAddress string
}

type ForwardManager struct {
	forwardMap map[string]*Forward
	mut        *sync.Mutex
}

func NewForwardManager() *ForwardManager {
	m := &ForwardManager{
		forwardMap: make(map[string]*Forward),
		mut:        &sync.Mutex{},
	}

	return m
}

func (m *ForwardManager) GetAll() map[string]*Forward {
	m.mut.Lock()
	defer m.mut.Unlock()

	mapCopy := make(map[string]*Forward)
	for k, v := range m.forwardMap {
		mapCopy[k] = &(*v)
	}

	return mapCopy
}

func (m *ForwardManager) Get(domain string) (*Forward, bool) {
	m.mut.Lock()
	defer m.mut.Unlock()

	forward, exists := m.forwardMap[domain]
	return forward, exists
}

func (m *ForwardManager) Set(domain string, forward *Forward) {
	m.mut.Lock()
	defer m.mut.Unlock()

	m.forwardMap[domain] = forward
}
