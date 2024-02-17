package waygate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/caddyserver/certmagic"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type Listener struct {
	listener     *PassthroughListener
	domain       string
	tunnelConfig TunnelConfig
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
func (l *Listener) GetTunnelConfig() TunnelConfig {
	return l.tunnelConfig
}
func Listen(token string) (*Listener, error) {
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
	}()

	l := &Listener{
		listener:     listener,
		domain:       tunConfig.Domain,
		tunnelConfig: tunConfig,
	}

	return l, nil
}
