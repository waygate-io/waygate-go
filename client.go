package waygate

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"

	"github.com/lastlogin-io/obligator"
)

var WaygateServerDomain string = "waygate.io"

type ClientConfig struct {
	Users        []string
	ServerDomain string
	Token        string
}

type Client struct {
	config  *ClientConfig
	eventCh chan interface{}
	// TODO: protect proxyMap with a mutex
	proxyMap   map[string]string
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
		config:   &configCopy,
		eventCh:  nil,
		proxyMap: make(map[string]string),
		tmpl:     tmpl,
	}
}

func (c *Client) ListenEvents(eventCh chan interface{}) {
	c.eventCh = eventCh
}

func (c *Client) Proxy(domain, addr string) {
	if domain == "" || addr == "" {
		return
	}

	c.proxyMap[domain] = addr
	printJson(c.proxyMap)
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

	fmt.Println("here", token)

	listener, err := Listen("tcp", "", token)
	if err != nil {
		return err
	}

	tunConfig := listener.GetTunnelConfig()

	dashUri := "https://dash." + tunConfig.Domain
	redirUriCh <- dashUri

	authDomain := "auth." + tunConfig.Domain
	authConfig := obligator.ServerConfig{
		RootUri: "https://" + authDomain,
		Prefix:  "waygate_client_auth_",
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

	mux := NewClientMux(authServer)

	httpClient := &http.Client{}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		upstreamAddr, exists := c.proxyMap[r.Host]
		if exists {
			proxyHttp(w, r, httpClient, upstreamAddr, false)
			return
		}

		tmplData := struct {
			Domains  []string
			Forwards map[string]string
		}{
			Domains:  []string{tunConfig.Domain},
			Forwards: c.proxyMap,
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

		subdomain := fmt.Sprintf("%s.%s", hostname, domain)

		c.proxyMap[subdomain] = targetAddr
		printJson(c.proxyMap)

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
}

func NewClientMux(authServer *obligator.Server) *ClientMux {
	m := &ClientMux{
		mux:        http.NewServeMux(),
		authServer: authServer,
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
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; script-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")

	host := r.Host

	authDomain := m.authServer.AuthDomains()[0]

	if host != authDomain {
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
	} else {
		m.authServer.ServeHTTP(w, r)
		return
	}

	m.mux.ServeHTTP(w, r)
}
