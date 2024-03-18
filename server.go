package waygate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/waygate-io/waygate-go/josencillo"
)

type ServerConfig struct {
	AdminDomain   string
	Port          int
	Public        bool
	DnsProvider   string
	DnsToken      string
	DnsUser       string
	TunnelDomains []string
}

type Server struct {
	jose   *josencillo.JOSE
	config *ServerConfig
	mut    *sync.Mutex
}

func NewServer(config *ServerConfig) *Server {

	s := &Server{
		config: config,
		mut:    &sync.Mutex{},
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
	exitOnError(err)

	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	if s.config.DnsProvider != "" {
		dnsProvider, err := getDnsProvider(s.config.DnsProvider, s.config.DnsToken, s.config.DnsUser)
		exitOnError(err)

		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSProvider: dnsProvider,
		}
	}

	//certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
	//	DecisionFunc: func(ctx context.Context, name string) error {
	//		// TODO: verify domain is in tunnels
	//		//if name != tunnelDomain {
	//		//	return fmt.Errorf("not allowed")
	//		//}
	//		return nil
	//	},
	//}

	certmagic.Default.Storage = &certmagic.FileStorage{"./certs"}

	certConfig := certmagic.NewDefault()

	challengeDomains := []string{}
	for _, domain := range s.config.TunnelDomains {
		challengeDomains = append(challengeDomains, "*."+domain)
	}

	ctx := context.Background()
	err = certConfig.ManageSync(ctx, append([]string{s.config.AdminDomain}, challengeDomains...))
	exitOnError(err)

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		// TODO: can we drop h2 here as long as we're not doing server TLS termination?
		NextProtos: []string{"http/1.1", "acme-tls/1", "waygate-tls-muxado"},
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
	exitOnError(err)

	s.jose, err = josencillo.NewJOSE()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	oauth2Prefix := "/oauth2"
	oauth2Handler := NewOAuth2Handler(oauth2Prefix, s.jose)

	//mux := http.NewServeMux()
	mux := NewServerMux(authServer, s.config.AdminDomain)

	mux.Handle(oauth2Prefix+"/", http.StripPrefix(oauth2Prefix, oauth2Handler))

	listenAddr := fmt.Sprintf(":%d", s.config.Port)
	tcpListener, err := net.Listen("tcp", listenAddr)
	exitOnError(err)

	wtServer := webtransport.Server{
		H3: http3.Server{
			Addr:      listenAddr,
			Handler:   mux,
			TLSConfig: tlsConfig,
			QuicConfig: &quic.Config{
				//MaxIncomingStreams: 512,
				KeepAlivePeriod: 8,
			},
		},
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	go wtServer.ListenAndServe()

	waygateListener := NewPassthroughListener()

	tunnels := make(map[string]Tunnel)

	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}

			s.mut.Lock()
			// TODO: I don't think this is actually a copy...
			tunnelsCopy := tunnels
			s.mut.Unlock()
			go func() {
				err := s.handleConn(tcpConn, authDomain, waygateListener, tunnelsCopy, tlsConfig)
				if err != nil {
					log.Println(err)
				}
			}()
		}
	}()

	tlsListener := tls.NewListener(waygateListener, tlsConfig)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Hi there</h1>"))
	})

	mux.HandleFunc("/waygate", func(w http.ResponseWriter, r *http.Request) {

		var tunnel Tunnel
		if r.ProtoMajor == 3 {
			wtTun, err := NewWebTransportServerTunnel(w, r, wtServer, s.jose, s.config.Public, s.config.TunnelDomains)
			if err != nil {
				w.WriteHeader(500)
				log.Println(err)
				return
			}

			tunnel = wtTun

			wtTun.HandleRequests(func(req interface{}) interface{} {
				switch r := req.(type) {
				case *ListenRequest:
					ln, err := net.Listen("tcp", r.Address)
					if err != nil {
						return &ListenResponse{
							Success: false,
							Message: err.Error(),
						}
					}

					go func() {
						for {
							conn, err := ln.Accept()
							if err != nil {
								fmt.Println("Failed to forward")
								continue
							}

							stream, err := wtTun.OpenStream()
							if err != nil {
								fmt.Println("Failed to open stream")
								continue
							}

							tcpConn := conn.(*net.TCPConn)

							proxyHeader, err := buildProxyProtoHeader(tcpConn, "")
							if err != nil {
								fmt.Println("Failed to build proxy header")
								continue
							}

							n, err := proxyHeader.WriteTo(stream)
							if err != nil {
								fmt.Println("Failed to write PROXY protocol header", n, err)
								continue
							}

							ConnectConns(tcpConn, stream)
						}
					}()

					return &ListenResponse{
						Success: true,
					}
				default:
					fmt.Println("Invalid request type")
					return nil
				}

				return nil
			})

		} else {
			tunnel, err = NewWebSocketMuxadoServerTunnel(w, r, s.jose, s.config.Public, s.config.TunnelDomains)
			if err != nil {
				w.WriteHeader(500)
				log.Println(err)
				return
			}
		}

		s.mut.Lock()
		defer s.mut.Unlock()
		domain := tunnel.GetConfig().Domain
		tunnels[domain] = tunnel
	})

	http.Serve(tlsListener, mux)
}

func (s *Server) handleConn(
	tcpConn net.Conn,
	authDomain string,
	waygateListener *PassthroughListener,
	tunnels map[string]Tunnel,
	tlsConfig *tls.Config) error {

	clientHello, clientReader, err := peekClientHello(tcpConn)
	if err != nil {
		return err
	}

	passConn := NewProxyConn(tcpConn, clientReader)

	if clientHello.ServerName == s.config.AdminDomain && isTlsMuxado(clientHello) {

		tlsConn := tls.Server(passConn, tlsConfig)

		tunnel, err := NewTlsMuxadoServerTunnel(tlsConn, s.jose, s.config.Public)
		if err != nil {
			return err
		}

		s.mut.Lock()
		defer s.mut.Unlock()
		domain := tunnel.GetConfig().Domain
		tunnels[domain] = tunnel

	} else if clientHello.ServerName == s.config.AdminDomain || clientHello.ServerName == authDomain {
		waygateListener.PassConn(passConn)
	} else {

		var tunnel Tunnel
		matched := false
		for _, tun := range tunnels {
			if strings.HasSuffix(clientHello.ServerName, tun.GetConfig().Domain) {
				tunnel = tun
				matched = true
				break
			}
		}

		if !matched {
			return errors.New(fmt.Sprintf("No such tunnel: %s", clientHello.ServerName))
		}

		upstreamConn, err := tunnel.OpenStream()
		if err != nil {
			return err
		}

		var conn connCloseWriter = passConn

		//negotiatedProto := ""
		if tunnel.GetConfig().TerminationType == "server" {
			tlsConn := tls.Server(passConn, tlsConfig)
			err := tlsConn.Handshake()
			if err != nil {
				return err
			}

			//connState := tlsConn.ConnectionState()
			//printJson(connState)
			//negotiatedProto = connState.NegotiatedProtocol

			conn = tlsConn
		}

		host, port, err := addrToHostPort(conn.RemoteAddr())
		if err != nil {
			return err
		}

		localHost, localPort, err := addrToHostPort(conn.LocalAddr())
		if err != nil {
			return err
		}

		remoteIp, isIPv4, err := parseIP(host)
		if err != nil {
			return err
		}

		localIp, _, err := parseIP(localHost)
		if err != nil {
			return err
		}

		transportProto := proxyproto.TCPv4
		if !isIPv4 {
			transportProto = proxyproto.TCPv6
		}

		if tunnel.GetConfig().UseProxyProtocol {
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

	return nil
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

			redirectUri := fmt.Sprintf("https://%s/%s?%s", host, r.URL.Path, r.URL.RawQuery)

			authUri := m.authServer.AuthUri(&obligator.OAuth2AuthRequest{
				// https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
				ResponseType: "none",
				ClientId:     url.QueryEscape("https://" + m.adminDomain),
				RedirectUri:  url.QueryEscape(redirectUri),
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

func isTlsMuxado(clientHello *tls.ClientHelloInfo) bool {
	for _, proto := range clientHello.SupportedProtos {
		if proto == "waygate-tls-muxado" {
			return true
		}
	}
	return false
}
