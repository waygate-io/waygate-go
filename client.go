package waygate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type ClientConfig struct {
	ServerDomain string
	Token        string
}

type Client struct {
}

func NewClient(config *ClientConfig) *Client {

	var tunConfig TunnelConfig

	tlsTermination := "client"

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
			if name != tunConfig.Domain {
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

	token := config.Token

	if token == "" {
		token, err = getToken(fmt.Sprintf("https://%s/oauth2/authorize", config.ServerDomain))
		if err != nil {
			panic(err)
		}
	}

	wsConn, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s", config.ServerDomain, token, tlsTermination), nil)
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

			var conn net.Conn = downstreamConn

			if tlsTermination == "client" {
				conn = tls.Server(downstreamConn, tlsConfig)
			}

			upstreamConn, err := net.Dial("tcp", "127.0.0.1:8080")
			if err != nil {
				log.Println("Error dialing")
				return
			}

			ConnectConns(conn, upstreamConn)
		}()
	}

	return nil
}

func getToken(authServerUri string) (string, error) {
	port, err := randomOpenPort()
	if err != nil {
		return "", err
	}

	localUri := fmt.Sprintf("http://localhost:%d", port)

	authUri := obligator.AuthUri(authServerUri, &obligator.OAuth2AuthRequest{
		ClientId:     localUri,
		RedirectUri:  fmt.Sprintf("%s/oauth2/callback", localUri),
		ResponseType: "code",
		Scope:        "waygate",
		State:        "TODO",
	})

	fmt.Println(authUri)

	mux := http.NewServeMux()

	listenStr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:    listenStr,
		Handler: mux,
	}

	token := ""

	mux.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("callback")
		token = "yolo"
		go func() {
			server.Shutdown(context.Background())
		}()
	})

	server.ListenAndServe()

	return token, nil
}
