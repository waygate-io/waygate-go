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
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type ServerConfig struct {
	AdminDomain string
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
	}
	authServer := obligator.NewServer(authConfig)

	mux := http.NewServeMux()

	tcpListener, err := net.Listen("tcp", ":9443")
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

			log.Println("got tcpConn")

			clientHello, clientReader, err := peekClientHello(tcpConn)
			if err != nil {
				log.Println("peekClientHello error", err)
				continue
			}

			passConn := NewProxyConn(tcpConn, clientReader)

			if clientHello.ServerName == s.config.AdminDomain || clientHello.ServerName == authDomain {
				waygateListener.PassConn(passConn)
			} else {
				mut.Lock()
				tunnel, exists := tunnels[clientHello.ServerName]
				mut.Unlock()

				muxSess := tunnel.muxSess
				terminationType := tunnel.config.TerminationType

				if !exists {
					log.Println("No such tunnel")
					continue
				}

				upstreamConn, err := muxSess.Open()
				if err != nil {
					log.Println(err)
					panic(err)
				}

				go func() {

					var conn net.Conn = passConn

					if terminationType == "server" {
						conn = tls.Server(passConn, tlsConfig)
					}

					ConnectConns(conn, upstreamConn)
				}()
			}
		}
	}()

	tlsListener := tls.NewListener(waygateListener, tlsConfig)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host

		switch host {
		case s.config.AdminDomain:
			_, err := authServer.Validate(r)
			if err != nil {
				redirectUri := fmt.Sprintf("https://%s/oauth2/callback", s.config.AdminDomain)
				url := fmt.Sprintf("https://%s/auth?client_id=%s&redirect_uri=%s&response_type=code&state=&scope=",
					authDomain, redirectUri, redirectUri)
				http.Redirect(w, r, url, 303)
				return
			}

			w.Write([]byte("<h1>Hi there</h1>"))
		case authDomain:
			authServer.ServeHTTP(w, r)
		}
	})

	// It would be nice if there was a way to tell obligator not to include query params
	// when redirecting back so we can avoid this extra redirect to strip them.
	mux.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://%s", s.config.AdminDomain), 307)
	})

	mux.HandleFunc("/waygate", func(w http.ResponseWriter, r *http.Request) {

		token := r.URL.Query().Get("token")
		if token != "yolo" {
			w.WriteHeader(401)
			log.Println(errors.New("Invalid token"))
			return
		}

		domain := fmt.Sprintf("test.%s", s.config.AdminDomain)

		terminationType := r.URL.Query().Get("termination-type")

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			w.WriteHeader(500)
			log.Println(err)
			return
		}

		tunConfig := TunnelConfig{
			Domain:          domain,
			TerminationType: terminationType,
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
