package waygate

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/caddyserver/certmagic"
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
	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	certConfig := certmagic.NewDefault()

	err := certConfig.ManageSync(context.Background(), []string{s.config.AdminDomain})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hi there"))
	})

	tcpListener, err := net.Listen("tcp", ":9443")
	if err != nil {
		panic(err)
	}

	waygateListener := NewPassthroughListener()

	tunnels := make(map[string]muxado.Session)
	mut := &sync.Mutex{}
	ctx := context.Background()

	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				fmt.Println(err)
				continue
			}

			clientHello, clientReader, err := peekClientHello(tcpConn)
			if err != nil {
				log.Println("peekClientHello error", err)
				continue
			}

			passConn := NewProxyConn(tcpConn, clientReader)

			if clientHello.ServerName == s.config.AdminDomain {
				waygateListener.PassConn(passConn)
			} else {
				mut.Lock()
				muxSess, exists := tunnels[clientHello.ServerName]
				mut.Unlock()

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
					ConnectConns(passConn, upstreamConn)
				}()
			}
		}
	}()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		// TODO: can we drop h2 here as long as we're not doing server TLS termination?
		NextProtos: []string{"h2", "acme-tls/1"},
	}
	tlsListener := tls.NewListener(waygateListener, tlsConfig)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		domain := r.URL.Query().Get("domain")

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			w.WriteHeader(500)
			log.Println(err)
			return
		}

		sessConn := websocket.NetConn(ctx, c, websocket.MessageBinary)

		muxSess := muxado.Server(sessConn, nil)

		mut.Lock()
		defer mut.Unlock()
		tunnels[domain] = muxSess
	})

	http.Serve(tlsListener, mux)
}

type ClientConfig struct {
	ServerDomain string
	AdminDomain  string
}

type Client struct {
}

func NewClient(config *ClientConfig) *Client {

	tunnelDomain := config.AdminDomain

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
			if name != tunnelDomain {
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

	wsConn, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://%s/?domain=%s", config.ServerDomain, tunnelDomain), nil)
	if err != nil {
		panic(err)
	}

	sessConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	muxSess := muxado.Client(sessConn, nil)

	log.Println("Got client")

	for {
		downstreamConn, err := muxSess.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go func() {

			log.Println("Got stream")

			tlsConn := tls.Server(downstreamConn, tlsConfig)

			err := tlsConn.Handshake()
			if err != nil {
				log.Println(err)
			}

			connState := tlsConn.ConnectionState()

			if connState.ServerName == tunnelDomain {

				upstreamConn, err := net.Dial("tcp", "127.0.0.1:8080")
				if err != nil {
					log.Println("Error dialing")
					return
				}

				ConnectConns(tlsConn, upstreamConn)
			} else {
			}
		}()
	}

	return nil
}

func ConnectConns(downstreamConn net.Conn, upstreamConn net.Conn) {

	defer downstreamConn.Close()
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		pipeConns(downstreamConn, upstreamConn)
		wg.Done()
	}()

	go func() {
		pipeConns(upstreamConn, downstreamConn)
		wg.Done()
	}()

	wg.Wait()
}

func pipeConns(readConn net.Conn, writeConn net.Conn) {
	_, err := io.Copy(writeConn, readConn)
	if err != nil {
		log.Println("here")
		log.Println(err.Error())
	}

	switch conn := writeConn.(type) {
	case *net.TCPConn:
		log.Println("close TCPConn")
		conn.CloseWrite()
	case muxado.Stream:
		log.Println("close muxado.Stream")
		conn.CloseWrite()
	default:
		log.Printf("pipeConns close: %T\n", writeConn)
	}
}
