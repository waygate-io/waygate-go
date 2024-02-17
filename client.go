package waygate

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/lastlogin-io/obligator"
)

var WaygateServerDomain string = "waygate.io"

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

type ClientConfig struct {
	Users        []string
	ServerDomain string
	Token        string
}

type Client struct {
	config     *ClientConfig
	eventCh    chan interface{}
	proxyMap   map[string]string
	authServer *obligator.Server
}

func NewClient(config *ClientConfig) *Client {

	configCopy := *config

	if configCopy.ServerDomain == "" {
		configCopy.ServerDomain = "waygate.io"
	}

	return &Client{
		config:   &configCopy,
		eventCh:  nil,
		proxyMap: make(map[string]string),
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
			return nil
		}
	}

	listener, err := Listen(token)
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

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Welcome to Waygate Client</h1>"))
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
