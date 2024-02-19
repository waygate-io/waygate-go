package waygate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/waygate-io/waygate-go/josencillo"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type ServerConfig struct {
	AdminDomain string
	Port        int
}

type Server struct {
	config *ServerConfig
}

func NewServer(config *ServerConfig) *Server {

	s := &Server{
		config: config,
	}

	return s
}

func (s *Server) Run() {
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
			// TODO: verify domain is in tunnels
			//if name != tunnelDomain {
			//	return fmt.Errorf("not allowed")
			//}
			return nil
		},
	}
	certConfig := certmagic.NewDefault()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		// TODO: can we drop h2 here as long as we're not doing server TLS termination?
		NextProtos: []string{"http/1.1", "acme-tls/1"},
	}

	authDomain := "auth." + s.config.AdminDomain
	authConfig := obligator.ServerConfig{
		RootUri: "https://" + authDomain,
		Prefix:  "waygate_auth_",
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

	jose, err := josencillo.NewJOSE()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	oauth2Prefix := "/oauth2"
	oauth2Handler := NewOAuth2Handler(oauth2Prefix, jose)

	//mux := http.NewServeMux()
	mux := NewServerMux(authServer, s.config.AdminDomain)

	mux.Handle(oauth2Prefix+"/", http.StripPrefix(oauth2Prefix, oauth2Handler))

	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Port))
	if err != nil {
		panic(err)
	}

	waygateListener := NewPassthroughListener()

	tunnels := make(map[string]Tunnel)
	mut := &sync.Mutex{}
	ctx := context.Background()

	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}

			mut.Lock()
			tunnelsCopy := tunnels
			mut.Unlock()
			go s.handleConn(tcpConn, authDomain, waygateListener, tunnelsCopy, tlsConfig)
		}
	}()

	tlsListener := tls.NewListener(waygateListener, tlsConfig)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Hi there</h1>"))
	})

	mux.HandleFunc("/waygate", func(w http.ResponseWriter, r *http.Request) {

		tokenJwt := r.URL.Query().Get("token")
		if tokenJwt == "" {
			w.WriteHeader(401)
			log.Println(errors.New("Missing token"))
			return
		}

		claims, err := jose.ParseJWT(tokenJwt)
		if err != nil {
			w.WriteHeader(401)
			log.Println(err)
			return
		}

		//domain := fmt.Sprintf("test.%s", s.config.AdminDomain)
		domain := claims["domain"].(string)

		terminationType := r.URL.Query().Get("termination-type")

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			w.WriteHeader(500)
			log.Println(err)
			return
		}

		useProxyProto := r.URL.Query().Get("use-proxy-protocol") == "true"

		tunConfig := TunnelConfig{
			Domain:           domain,
			TerminationType:  terminationType,
			UseProxyProtocol: useProxyProto,
		}

		bytes, err := json.Marshal(tunConfig)
		if err != nil {
			w.WriteHeader(500)
			log.Println(err)
			return
		}

		err = c.Write(ctx, websocket.MessageBinary, bytes)
		if err != nil {
			w.WriteHeader(500)
			log.Println(err)
			return
		}

		sessConn := websocket.NetConn(ctx, c, websocket.MessageBinary)

		muxSess := muxado.Server(sessConn, nil)

		mut.Lock()
		defer mut.Unlock()
		tunnels[domain] = Tunnel{
			muxSess: muxSess,
			config:  tunConfig,
		}
	})

	http.Serve(tlsListener, mux)
}

func (s *Server) handleConn(
	tcpConn net.Conn,
	authDomain string,
	waygateListener *PassthroughListener,
	tunnels map[string]Tunnel,
	tlsConfig *tls.Config) {

	log.Println("got tcpConn")

	clientHello, clientReader, err := peekClientHello(tcpConn)
	if err != nil {
		log.Println("peekClientHello error", err)
		return
	}

	passConn := NewProxyConn(tcpConn, clientReader)

	if clientHello.ServerName == s.config.AdminDomain || clientHello.ServerName == authDomain {
		waygateListener.PassConn(passConn)
	} else {

		var tunnel Tunnel
		matched := false
		for _, tun := range tunnels {
			if strings.HasSuffix(clientHello.ServerName, tun.config.Domain) {
				tunnel = tun
				matched = true
				break
			}
		}

		if !matched {
			log.Println("No such tunnel")
			return
		}

		upstreamConn, err := tunnel.muxSess.OpenStream()
		if err != nil {
			log.Println(err)
			panic(err)
		}

		var conn connCloseWriter = passConn

		//negotiatedProto := ""
		if tunnel.config.TerminationType == "server" {
			tlsConn := tls.Server(passConn, tlsConfig)
			tlsConn.Handshake()
			if err != nil {
				log.Println(err)
				panic(err)
			}

			//connState := tlsConn.ConnectionState()
			//printJson(connState)
			//negotiatedProto = connState.NegotiatedProtocol

			conn = tlsConn
		}

		host, port, err := addrToHostPort(conn.RemoteAddr())
		if err != nil {
			log.Println(err)
			panic(err)
		}

		localHost, localPort, err := addrToHostPort(conn.LocalAddr())
		if err != nil {
			log.Println(err)
			panic(err)
		}

		if tunnel.config.UseProxyProtocol {
			proxyHeader := &proxyproto.Header{
				Version:           2,
				Command:           proxyproto.PROXY,
				TransportProtocol: proxyproto.TCPv4,
				SourceAddr: &net.TCPAddr{
					IP:   net.ParseIP(host),
					Port: port,
				},
				DestinationAddr: &net.TCPAddr{
					IP:   net.ParseIP(localHost),
					Port: localPort,
				},
			}

			proxyHeader.SetTLVs([]proxyproto.TLV{
				proxyproto.TLV{
					Type:  proxyproto.PP2_TYPE_MIN_CUSTOM,
					Value: []byte(clientHello.ServerName),
				},
			})

			//if negotiatedProto != "" {
			//	proxyHeader.SetTLVs([]proxyproto.TLV{
			//		proxyproto.TLV{
			//			Type:  proxyproto.PP2_TYPE_MIN_CUSTOM,
			//			Value: []byte(negotiatedProto),
			//		},
			//	})
			//}

			// TODO: I think this can possibly block and deadlock
			n, err := proxyHeader.WriteTo(upstreamConn)
			if err != nil {
				fmt.Println("Failed to write PROXY protocol header", n, err)
			}
		}

		ConnectConns(conn, upstreamConn)
	}
}

type ServerMux struct {
	mux         *http.ServeMux
	authServer  *obligator.Server
	adminDomain string
}

func NewServerMux(authServer *obligator.Server, adminDomain string) *ServerMux {
	m := &ServerMux{
		mux:         http.NewServeMux(),
		authServer:  authServer,
		adminDomain: adminDomain,
	}
	return m
}

func (m *ServerMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; script-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")

	host := r.Host

	authDomain := m.authServer.AuthDomains()[0]

	if r.URL.Path != "/waygate" && host != authDomain && r.URL.Path != "/oauth2/token" {
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
	} else if host == authDomain {
		m.authServer.ServeHTTP(w, r)
		return
	}

	//timestamp := time.Now().Format(time.RFC3339)

	//remoteIp, err := getRemoteIp(r, s.behindProxy)
	//if err != nil {
	//	w.WriteHeader(500)
	//	io.WriteString(w, err.Error())
	//	return
	//}

	//fmt.Println(fmt.Sprintf("%s\t%s\t%s\t%s\t%s", timestamp, remoteIp, r.Method, r.Host, r.URL.Path))
	m.mux.ServeHTTP(w, r)
}

func (s *ServerMux) Handle(p string, h http.Handler) {
	s.mux.Handle(p, h)
}

func (s *ServerMux) HandleFunc(p string, f func(w http.ResponseWriter, r *http.Request)) {
	s.mux.HandleFunc(p, f)
}
