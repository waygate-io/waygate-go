package waygate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

var WaygateServerDomain string = "waygate.io"

func Listen(token string, mux *http.ServeMux) (*Listener, error) {
	var tunConfig TunnelConfig

	tlsTermination := "client"
	//tlsTermination := "server"
	//useProxyProtoStr := "true"
	useProxyProtoStr := "false"

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	var err error
	certmagic.HTTPSPort, err = randomOpenPort()
	if err != nil {
		log.Println("Failed get random port for TLS challenges")
		panic(err)
	}

	certmagic.DefaultACME.DisableHTTPChallenge = true

	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			if !strings.HasSuffix(name, tunConfig.Domain) {
				return fmt.Errorf("not allowed")
			}
			return nil
		},
	}

	certConfig := certmagic.NewDefault()

	ctx := context.Background()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		//NextProtos:     []string{"h2", "acme-tls/1"},
		// TODO: re-enable h2 support, probably by proxying at the HTTP level
		NextProtos: []string{"http/1.1", "acme-tls/1"},
	}

	uri := fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s&use-proxy-protocol=%s",
		WaygateServerDomain,
		token,
		tlsTermination,
		useProxyProtoStr,
	)

	wsConn, _, err := websocket.Dial(ctx, uri, nil)
	if err != nil {
		return nil, err
	}

	_, tunConfigBytes, err := wsConn.Read(ctx)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(tunConfigBytes, &tunConfig)
	if err != nil {
		return nil, err
	}

	sessConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	muxSess := muxado.Client(sessConn, nil)

	listener := NewPassthroughListener()

	go func() {
		for {
			downstreamConn, err := muxSess.AcceptStream()
			if err != nil {
				// TODO: close on error
				log.Println(err)
				continue
			}

			go func() {

				log.Println("Got stream")

				var conn connCloseWriter = downstreamConn

				if tunConfig.UseProxyProtocol {
					reader := bufio.NewReader(conn)
					ppHeader, err := proxyproto.Read(reader)
					if err != nil {
						// TODO: close on error
						log.Println(err)
						return
					}

					tlvs, err := ppHeader.TLVs()
					if err != nil {
						log.Println(err)
						return
					}

					proto := string(tlvs[0].Value)

					printJson(ppHeader)
					printJson(tlvs)
					fmt.Println(proto)

				}

				if tlsTermination == "client" {
					conn = tls.Server(conn, tlsConfig)
				}

				// TODO: use addrs from PROXY protocol
				conn = wrapperConn{
					conn: conn,
					localAddr: addr{
						network: "dummy-network:0",
					},
					remoteAddr: addr{
						network: "dummy-network:0",
					},
				}

				listener.PassConn(conn)

			}()
		}
	}()

	l := &Listener{
		listener: listener,
		domain:   tunConfig.Domain,
	}

	return l, nil
}

type Listener struct {
	listener *PassthroughListener
	domain   string
}

func (l *Listener) Accept() (net.Conn, error) {
	return l.listener.Accept()
}
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}
func (l *Listener) Close() error {
	return l.listener.Close()
}
func (l *Listener) GetDomain() string {
	return l.domain
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

	var tunConfig TunnelConfig

	tlsTermination := "client"
	//tlsTermination := "server"
	//useProxyProtoStr := "true"
	useProxyProtoStr := "false"

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	var err error
	certmagic.HTTPSPort, err = randomOpenPort()
	if err != nil {
		log.Println("Failed get random port for TLS challenges")
		panic(err)
	}

	certmagic.DefaultACME.DisableHTTPChallenge = true

	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			if !strings.HasSuffix(name, tunConfig.Domain) {
				return fmt.Errorf("not allowed")
			}
			return nil
		},
	}

	certConfig := certmagic.NewDefault()

	ctx := context.Background()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		//NextProtos:     []string{"h2", "acme-tls/1"},
		// TODO: re-enable h2 support, probably by proxying at the HTTP level
		NextProtos: []string{"http/1.1", "acme-tls/1"},
	}

	uri := fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s&use-proxy-protocol=%s",
		c.config.ServerDomain,
		token,
		tlsTermination,
		useProxyProtoStr,
	)

	wsConn, _, err := websocket.Dial(ctx, uri, nil)
	if err != nil {
		panic(err)
	}

	_, tunConfigBytes, err := wsConn.Read(ctx)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(tunConfigBytes, &tunConfig)
	if err != nil {
		panic(err)
	}

	dashUri := "https://dash." + tunConfig.Domain
	redirUriCh <- dashUri

	sessConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	muxSess := muxado.Client(sessConn, nil)

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

	listener := NewPassthroughListener()

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

	for {
		downstreamConn, err := muxSess.AcceptStream()
		if err != nil {
			// TODO: close on error
			log.Println(err)
			continue
		}

		go func() {

			log.Println("Got stream")

			var conn connCloseWriter = downstreamConn

			if tunConfig.UseProxyProtocol {
				reader := bufio.NewReader(conn)
				ppHeader, err := proxyproto.Read(reader)
				if err != nil {
					// TODO: close on error
					log.Println(err)
					return
				}

				tlvs, err := ppHeader.TLVs()
				if err != nil {
					log.Println(err)
					return
				}

				proto := string(tlvs[0].Value)

				printJson(ppHeader)
				printJson(tlvs)
				fmt.Println(proto)

			}

			if tlsTermination == "client" {
				conn = tls.Server(conn, tlsConfig)
			}

			// TODO: use addrs from PROXY protocol
			conn = wrapperConn{
				conn: conn,
				localAddr: addr{
					network: "dummy-network:0",
				},
				remoteAddr: addr{
					network: "dummy-network:0",
				},
			}

			listener.PassConn(conn)

			//ip := "127.0.0.1"
			//port := 8000

			//proxyAddr, exists := c.proxyMap[tunConfig.Domain]
			//if exists {
			//	var portStr string
			//	ip, portStr, err = net.SplitHostPort(proxyAddr)
			//	if err != nil {
			//		log.Println("Error splitting address")
			//		return
			//	}

			//	port, err = strconv.Atoi(portStr)
			//	if err != nil {
			//		log.Println("Error parsing port")
			//		return
			//	}
			//}

			//upstreamConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
			//	IP:   net.ParseIP(ip),
			//	Port: port,
			//})
			//if err != nil {
			//	log.Println("Error dialing")
			//	return
			//}

			//ConnectConns(conn, upstreamConn)
		}()
	}
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
