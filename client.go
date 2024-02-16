package waygate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	//"net"
	"net/http"
	"net/url"
	//"strconv"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type TunnelConnectedEvent struct {
	TunnelConfig TunnelConfig
}

type OAuth2AuthUriEvent struct {
	Uri string
}

type ClientMux struct {
	mux         *http.ServeMux
	authServer  *obligator.Server
	adminDomain string
}

func NewClientMux(authServer *obligator.Server, adminDomain string) *ClientMux {
	m := &ClientMux{
		mux:         http.NewServeMux(),
		authServer:  authServer,
		adminDomain: adminDomain,
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

			redirectUri := fmt.Sprintf("https://%s", m.adminDomain)

			authUri := m.authServer.AuthUri(&obligator.OAuth2AuthRequest{
				// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
				ResponseType: "none",
				ClientId:     "https://" + m.adminDomain,
				RedirectUri:  redirectUri,
				State:        "",
				Scope:        "",
			})

			http.Redirect(w, r, authUri, 303)
			return
		}

		fmt.Println("here")
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
	config   *ClientConfig
	eventCh  chan interface{}
	proxyMap map[string]string
}

func NewClient(config *ClientConfig) *Client {

	configCopy := *config

	if configCopy.ServerDomain == "" {
		configCopy.ServerDomain = "waygate.io"
	}

	if len(configCopy.Users) == 0 {
		panic("Must provide a user")
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
		var err error
		token, err = c.getToken(fmt.Sprintf("https://%s/oauth2", c.config.ServerDomain), redirUriCh)
		if err != nil {
			panic(err)
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

	if c.eventCh != nil {
		c.eventCh <- TunnelConnectedEvent{
			TunnelConfig: tunConfig,
		}
	}

	authDomain := "auth." + tunConfig.Domain
	authConfig := obligator.ServerConfig{
		RootUri: "https://" + authDomain,
		Prefix:  "waygate_client_auth_",
	}
	authServer := obligator.NewServer(authConfig)
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

	err = authServer.AddUser(obligator.User{
		Email: c.config.Users[0],
	})
	if err != nil {
		fmt.Println(err)
	}

	mux := NewClientMux(authServer, tunConfig.Domain)

	listener := NewPassthroughListener()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Welcome to Waygate Client</h1>"))
	})

	go http.Serve(listener, mux)

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

func (c *Client) getToken(authServerUri string, redirUriCh chan string) (string, error) {
	port, err := randomOpenPort()
	if err != nil {
		return "", err
	}

	localUri := fmt.Sprintf("http://localhost:%d", port)

	state, err := genRandomText(32)
	if err != nil {
		return "", err
	}

	authUri := obligator.AuthUri(authServerUri+"/authorize", &obligator.OAuth2AuthRequest{
		ClientId:     localUri,
		RedirectUri:  fmt.Sprintf("%s/oauth2/callback", localUri),
		ResponseType: "code",
		Scope:        "waygate",
		State:        state,
	})

	if c.eventCh != nil {
		c.eventCh <- OAuth2AuthUriEvent{
			Uri: authUri,
		}
	}

	mux := http.NewServeMux()

	listenStr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:    listenStr,
		Handler: mux,
	}

	tokenCh := make(chan string)

	mux.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		stateParam := r.Form.Get("state")
		if stateParam != state {
			w.WriteHeader(500)
			io.WriteString(w, "Invalid state param")
			return
		}

		code := r.Form.Get("code")

		httpClient := &http.Client{}

		params := url.Values{}
		params.Set("code", code)
		body := strings.NewReader(params.Encode())

		tokenUri := fmt.Sprintf("%s/token", authServerUri)

		req, err := http.NewRequest(http.MethodPost, tokenUri, body)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err := httpClient.Do(req)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		//if res.StatusCode != 200 {
		//	w.WriteHeader(500)
		//	io.WriteString(w, "Bad HTTP response code")
		//	return
		//}

		var tokenRes obligator.OAuth2TokenResponse

		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = json.Unmarshal(bodyBytes, &tokenRes)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		//err = json.NewDecoder(res.Body).Decode(&tokenRes)
		//if err != nil {
		//	w.WriteHeader(500)
		//	io.WriteString(w, err.Error())
		//	return
		//}

		tokenCh <- tokenRes.AccessToken

		redirUri := <-redirUriCh

		go func() {
			server.Shutdown(context.Background())
		}()

		http.Redirect(w, r, redirUri, 303)
	})

	go server.ListenAndServe()

	token := <-tokenCh

	return token, nil
}
