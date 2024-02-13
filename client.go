package waygate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/lastlogin-io/obligator"
	proxyproto "github.com/pires/go-proxyproto"
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
	//tlsTermination := "server"
	useProxyProtoStr := "true"

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
		token, err = getToken(fmt.Sprintf("https://%s/oauth2", config.ServerDomain))
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("Token")
	printJson(token)

	uri := fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s&use-proxy-protocol=%s",
		config.ServerDomain,
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

	sessConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	muxSess := muxado.Client(sessConn, nil)

	log.Println("Got client")

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
				_, err := proxyproto.Read(reader)
				if err != nil {
					// TODO: close on error
					log.Println(err)
					return
				}

			}

			if tlsTermination == "client" {
				conn = tls.Server(conn, tlsConfig)
			}

			upstreamConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 8080,
			})
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

	fmt.Println(authUri)

	mux := http.NewServeMux()

	listenStr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:    listenStr,
		Handler: mux,
	}

	token := ""

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

		fmt.Println("params", params.Encode())

		tokenUri := fmt.Sprintf("%s/token", authServerUri)

		fmt.Println("tokenUri", tokenUri)

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

		token = tokenRes.AccessToken

		go func() {
			server.Shutdown(context.Background())
		}()
	})

	server.ListenAndServe()

	return token, nil
}
