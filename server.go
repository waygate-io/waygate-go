package waygate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	//"net/url"
	"strings"
	"sync"
	"time"
	//_ "expvar"

	"github.com/anderspitman/dashtui"
	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-net/decent-auth-go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/takingnames/namedrop-go"
	"github.com/waygate-io/waygate-go/josencillo"
	"go.uber.org/zap"
)

type ServerConfig struct {
	AdminDomain      string
	Port             int
	Public           bool
	DnsProvider      string
	DnsToken         string
	DnsUser          string
	TunnelDomains    []string
	DisableTUI       bool
	TUIDisplayPeriod time.Duration
	Users            []string
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

var count int = 0
var dash *dashtui.DashTUI

func (s *Server) Run() int {

	var err error
	dash, err = dashtui.NewBuilder().
		Disable(s.config.DisableTUI).
		DisplayPeriod(s.config.TUIDisplayPeriod).
		Build()
	if err != nil {
		log.Fatalf("failed to initialize dashtui: %v", err)
	}
	defer dash.Close()

	db, err := NewDatabase("waygate_server_db.sqlite3")
	exitOnError(err)

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the boringproxy client is likely to be
	// running on a machine where 443 isn't bound, so we need a different
	// port to hack around this. See here for more details:
	// https://github.com/caddyserver/certmagic/issues/111
	certmagic.HTTPSPort, err = randomOpenPort()
	exitOnError(err)

	if len(s.config.Users) > 0 {
		certmagic.DefaultACME.Email = s.config.Users[0]
	}
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.Agreed = true
	certmagic.Default.Logger = zap.NewNop()
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	// TODO: maybe perform this check on listen and use a separate certmagic object for each tunnel
	if s.config.DnsProvider != "" {
		dnsProvider, err := getDnsProvider(s.config.DnsProvider, s.config.DnsToken, s.config.DnsUser)
		exitOnError(err)

		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: dnsProvider,
			},
		}
	} else {
		//certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		//	DecisionFunc: func(ctx context.Context, name string) error {
		//		// TODO: verify domain is in tunnels
		//		//if name != tunnelDomain {
		//		//	return fmt.Errorf("not allowed")
		//		//}
		//		return nil
		//	},
		//}
	}

	//certmagic.Default.Storage = &certmagic.FileStorage{"./certs"}
	certmagic.Default.Storage, err = NewCertmagicSqliteStorage(db.db.DB)
	exitOnError(err)

	certConfig := certmagic.NewDefault()

	challengeDomains := []string{}
	for _, domain := range s.config.TunnelDomains {
		challengeDomains = append(challengeDomains, "*."+domain)
	}

	publicIp, err := namedrop.GetPublicIp("takingnames.io/namedrop", "tcp4")
	exitOnError(err)

	addrs, err := net.LookupHost(s.config.AdminDomain)
	exitOnError(err)

	found := false
	for _, addr := range addrs {
		if addr == publicIp {
			found = true
			break
		}
	}

	if !found {
		msg := fmt.Sprintf("The domain '%s' does not appear to be pointed at this server\n", s.config.AdminDomain)
		exitOnError(errors.New(msg))
	}

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		// TODO: can we drop h2 here as long as we're not doing server TLS termination?
		NextProtos: []string{"http/1.1", "acme-tls/1", "waygate-tls-muxado"},
	}

	authPrefix := "/auth"

	kvStore, err := decentauth.NewSqliteKvStore(&decentauth.SqliteKvOptions{
		Db:        db.db.DB,
		TableName: "auth_kv",
	})
	exitOnError(err)

	authHandler, err := decentauth.NewHandler(&decentauth.HandlerOptions{
		KvStore: kvStore,
		Config: decentauth.Config{
			PathPrefix:  authPrefix,
			AdminID:     s.config.Users[0],
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

	jwksJson, err := db.GetJWKS()
	if err != nil {
		s.jose, err = josencillo.NewJOSE()
		exitOnError(err)

		jwksJson, err := s.jose.GetJwksJson()
		exitOnError(err)

		err = db.SetJWKS(jwksJson)
		exitOnError(err)
	} else {
		s.jose, err = josencillo.NewWithJwkJson(jwksJson)
		exitOnError(err)
	}

	tmpl, err := template.ParseFS(fs, "templates/*")
	exitOnError(err)

	serverUri := "https://" + s.config.AdminDomain
	oauth2Prefix := "/oauth2"
	oauth2Handler := NewOAuth2Handler(db, serverUri, oauth2Prefix, s.jose, tmpl)

	//mux := http.NewServeMux()
	mux := NewServerMux(authHandler, s.config.AdminDomain, s.config.Users[0])

	numStreamsGauge := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "waygate_num_streams",
		Help: "Number of active streams",
	})
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":9500", nil)

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

	httpServer := &http.Server{
		Handler: mux,
	}

	exitReason := "normal"

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
				err := s.handleConn(tcpConn, waygateListener, tunnelsCopy, tlsConfig)
				if err != nil {
					log.Println(err)
				}
			}()
		}
	}()

	tlsListener := tls.NewListener(waygateListener, tlsConfig)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		fmt.Println(r.URL.Path)

		tmplData := struct {
		}{}

		err = tmpl.ExecuteTemplate(w, "server.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.Handle(authPrefix+"/", authHandler)

	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		exitReason = "shutdown"
		exit(w, r, tmpl, httpServer)
	})

	mux.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		exitReason = "restart"
		exit(w, r, tmpl, httpServer)
	})

	mux.HandleFunc("/waygate", func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("/waygate")

		var tunnel Tunnel
		if r.ProtoMajor == 3 {
			wtTun, err := NewWebTransportServerTunnel(w, r, wtServer, s.jose, s.config.Public, s.config.TunnelDomains)
			if err != nil {
				w.WriteHeader(500)
				log.Println(err)
				return
			}

			tunnel = wtTun

		} else {
			//tunnel, err = NewWebSocketMuxadoServerTunnel(w, r, s.jose, s.config.Public, s.config.TunnelDomains, numStreamsGauge)
			tunnel, err = NewOmnistreamsServerTunnel(w, r, s.jose, s.config.Public, s.config.TunnelDomains, numStreamsGauge, dash)
			if err != nil {
				w.WriteHeader(500)
				log.Println("NewOmnistreamsClientTunnel error", err)
				return
			}
		}

		udpMap := make(map[string]*net.UDPConn)
		mut := &sync.Mutex{}

		// TODO: if this goroutine exits unexpectedly we probably need to shut it down.
		go func() {

			for {
				dgram, _, dstAddr, err := tunnel.ReceiveDatagram()
				if err != nil {
					fmt.Println(err)
					break
				}

				mut.Lock()
				conn := udpMap[dstAddr.String()]
				mut.Unlock()

				dstUDPAddr, err := net.ResolveUDPAddr("udp", dstAddr.String())
				if err != nil {
					fmt.Println("ResolveUDPAddr:", err)
					break
				}

				n, err := conn.WriteToUDP(dgram, dstUDPAddr)
				if err != nil {
					fmt.Println(err)
					break
				}

				if n != len(dgram) {
					fmt.Println(err)
					break
				}
			}
		}()

		tunnel.HandleRequests(func(req interface{}) interface{} {
			switch r := req.(type) {
			case *DialRequest:
				udpAddr, err := net.ResolveUDPAddr("udp", r.Address)
				if err != nil {
					return &DialResponse{
						Success: false,
						Message: err.Error(),
					}
				}

				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					return &DialResponse{
						Success: false,
						Message: err.Error(),
					}
				}

				mut.Lock()
				udpMap[r.Address] = conn
				mut.Unlock()

				srcAddr := conn.RemoteAddr()
				dstAddr := conn.LocalAddr()

				go func() {
					buf := make([]byte, 64*1024)

					for {
						n, err := conn.Read(buf)
						if err != nil {
							fmt.Println("Failed to forward:", err)
							continue
						}

						tunnel.SendDatagram(buf[:n], srcAddr, dstAddr)
					}
				}()

				return &DialResponse{
					Success: true,
					Address: dstAddr.String(),
				}

			case *ListenRequest:
				if strings.HasPrefix(r.Network, "tls") {
					fmt.Println(r)
					domain := r.Address
					s.mut.Lock()
					tunnels[domain] = tunnel
					s.mut.Unlock()
				} else if strings.HasPrefix(r.Network, "tcp") {
					_, err = handleListenTCP(tunnel, r.Address)
					if err != nil {
						return &ListenResponse{
							Success: false,
							Message: err.Error(),
						}
					}
				} else {
					_, err = handleListenUDP(tunnel, r.Address, udpMap, s.mut)
					if err != nil {
						return &ListenResponse{
							Success: false,
							Message: err.Error(),
						}
					}
				}

				return &ListenResponse{
					Success: true,
				}
			default:
				fmt.Println("Invalid request type")
				return nil
			}

			return nil
		})

		s.mut.Lock()
		defer s.mut.Unlock()
		domain := tunnel.GetConfig().Domain
		tunnels[domain] = tunnel
	})

	waitCh := make(chan struct{})

	go func() {
		err = httpServer.Serve(tlsListener)
		fmt.Println("here", err)
		waitCh <- struct{}{}
	}()

	ctx := context.Background()
	//adminDomains := []string{s.config.AdminDomain, "*." + s.config.AdminDomain}
	//err = certConfig.ManageSync(ctx, append(adminDomains, challengeDomains...))
	adminDomains := []string{s.config.AdminDomain}
	err = certConfig.ManageSync(ctx, adminDomains)
	exitOnError(err)

	<-waitCh

	switch exitReason {
	case "restart":
		return 64
	case "shutdown":
		return 0
	default:
		return 0
	}
}

func (s *Server) handleConn(
	tcpConn net.Conn,
	waygateListener *PassthroughListener,
	tunnels map[string]Tunnel,
	tlsConfig *tls.Config) error {

	clientHello, clientReader, err := peekClientHello(tcpConn)
	if err != nil {
		return err
	}

	passConn := NewProxyConn(tcpConn, clientReader)

	if clientHello.ServerName == s.config.AdminDomain && isTlsMuxado(clientHello) {

		return errors.New("Muxado TLS not implemented")
		//tlsConn := tls.Server(passConn, tlsConfig)

		//tunnel, err := NewTlsMuxadoServerTunnel(tlsConn, s.jose, s.config.Public)
		//if err != nil {
		//	return err
		//}

		//s.mut.Lock()
		//defer s.mut.Unlock()
		//domain := tunnel.GetConfig().Domain
		//tunnels[domain] = tunnel

	} else if clientHello.ServerName == s.config.AdminDomain {
		waygateListener.PassConn(passConn)
	} else {

		var tunnel Tunnel
		matched := false
		for domain, tun := range tunnels {
			if strings.HasSuffix(clientHello.ServerName, domain) {
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

		if tunnel.GetConfig().TerminationType == "server" {
			tlsConn := tls.Server(passConn, tlsConfig)
			conn = tlsConn
		}

		if tunnel.GetConfig().UseProxyProtocol {
			proxyHeader, err := buildProxyProtoHeader(conn, clientHello.ServerName)

			n, err := proxyHeader.WriteTo(upstreamConn)
			if err != nil {
				fmt.Println("Failed to write PROXY protocol header", n, err)
			}
		}

		ConnectConns(conn, upstreamConn)
	}

	return nil
}

func handleListenTCP(wtTun Tunnel, addr string) (net.Listener, error) {

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Println("Failed to forward")
				break
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

			go ConnectConns(tcpConn, stream)
		}
	}()

	go func() {
		events := wtTun.Events()
		evt := <-events
		switch evt.(type) {
		case TunnelEventClose:
			err := ln.Close()
			if err != nil {
				fmt.Println("handleListenTCP close listener", err)
			}
		}
	}()

	return ln, nil
}

func handleListenUDP(tunnel Tunnel, listenAddr string, udpMap map[string]*net.UDPConn, mut *sync.Mutex) (*net.UDPConn, error) {

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	downstreamConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}

	go func() {

		buf := make([]byte, 64*1024)

		for {
			n, srcAddr, err := downstreamConn.ReadFromUDP(buf)
			if err != nil {
				fmt.Println("Failed to forward")
				break
			}

			_, exists := udpMap[srcAddr.String()]
			if !exists {
				mut.Lock()
				udpMap[srcAddr.String()] = downstreamConn
				mut.Unlock()
			}

			dstAddr := downstreamConn.LocalAddr()

			err = tunnel.SendDatagram(buf[:n], srcAddr, dstAddr)
			if err != nil {
				fmt.Println(err)
			}
		}
	}()

	go func() {
		events := tunnel.Events()
		evt := <-events
		switch evt.(type) {
		case TunnelEventClose:
			err := downstreamConn.Close()
			if err != nil {
				fmt.Println("handleListenUDP close downstreamConn", err)
			}
		}
	}()

	return downstreamConn, nil
}

type ServerMux struct {
	mux         *http.ServeMux
	authHandler *decentauth.Handler
	adminDomain string
	adminID     string
}

func NewServerMux(authHandler *decentauth.Handler, adminDomain, adminID string) *ServerMux {
	m := &ServerMux{
		mux:         http.NewServeMux(),
		authHandler: authHandler,
		adminDomain: adminDomain,
		adminID:     adminID,
	}
	return m
}

func (m *ServerMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'; script-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")

	authPrefix := "/auth"

	if !strings.HasPrefix(r.URL.Path, authPrefix) && r.URL.Path != "/waygate" && r.URL.Path != "/oauth2/token" && r.URL.Path != "/oauth2/device" && r.URL.Path != "/oauth2/device-verify" {

		session := m.authHandler.GetSession(r)
		if session == nil {
			http.Redirect(w, r, authPrefix, 303)
			return
		} else if session.Id != m.adminID {
			http.Redirect(w, r, authPrefix+"/logout", 303)
			return
		}
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
