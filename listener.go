package waygate

import (
	"errors"
	"sync"
	//"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/mailgun/proxyproto"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

const PROXY_PROTO_PP2_TYPE_MIN_CUSTOM = 0xe0
const PROXY_PROTO_SERVER_NAME_OFFSET = PROXY_PROTO_PP2_TYPE_MIN_CUSTOM + 0
const LISTENER_KEY_DEFAULT = "default-listener"

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
func Listen(network, address, token string) (*Listener, error) {

	s, err := NewClientSession(token)
	if err != nil {
		return nil, err
	}

	return s.Listen(network, address)
}

type ClientSession struct {
	muxSess        muxado.Session
	tlsConfig      *tls.Config
	tunConfig      TunnelConfig
	tlsTermination string
	listenMap      map[string]*PassthroughListener
	mut            *sync.Mutex
}

func NewClientSession(token string) (*ClientSession, error) {
	var tunConfig TunnelConfig

	tlsTermination := "client"
	//tlsTermination := "server"
	useProxyProtoStr := "true"
	//useProxyProtoStr := "false"

	// Use random unprivileged port for ACME challenges. This is necessary
	// because of the way certmagic works, in that if it fails to bind
	// HTTPSPort (443 by default) and doesn't detect anything else binding
	// it, it fails. Obviously the waygate client is likely to be
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

	s := &ClientSession{
		muxSess:        muxSess,
		tlsConfig:      tlsConfig,
		tunConfig:      tunConfig,
		tlsTermination: tlsTermination,
		listenMap:      make(map[string]*PassthroughListener),
		mut:            &sync.Mutex{},
	}

	s.start()

	return s, nil
}

func (s *ClientSession) start() {

	go func() {
		for {
			downstreamConn, err := s.muxSess.AcceptStream()
			if err != nil {
				// TODO: close on error
				log.Println(err)
				continue
			}

			go func() {

				var conn connCloseWriter = downstreamConn

				serverName := ""
				if s.tunConfig.UseProxyProtocol {
					ppHeader, err := proxyproto.ReadHeader(conn)
					if err != nil {
						log.Println(err)
						return
					}

					tlvs, err := ppHeader.ParseTLVs()
					if err != nil {
						log.Println(err)
						return
					}

					serverName = string(tlvs[PROXY_PROTO_SERVER_NAME_OFFSET])
				}

				if s.tlsTermination == "client" {
					conn = tls.Server(conn, s.tlsConfig)
				}

				// TODO: use addrs from PROXY protocol
				conn = wrapperConn{
					conn: conn,
					localAddr: addr{
						network: "dummy-network",
						address: "dummy-address:0",
					},
					remoteAddr: addr{
						network: "dummy-network",
						address: "dummy-address:0",
					},
				}

				s.mut.Lock()
				defer s.mut.Unlock()

				listener, exists := s.listenMap[serverName]
				if !exists {
					listener, exists = s.listenMap[LISTENER_KEY_DEFAULT]
					if !exists {
						fmt.Println("No such listener")
						conn.Close()
						return
					}
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
}

func (s *ClientSession) GetTunnelConfig() TunnelConfig {
	return s.tunConfig
}

func (s *ClientSession) Listen(network, address string) (*Listener, error) {

	if network != "tcp" && network != "tcp4" {
		return nil, errors.New(fmt.Sprintf("Invalid network type: %s", network))
	}

	if address == "" {
		address = LISTENER_KEY_DEFAULT
	}

	ip := net.ParseIP(address)
	fmt.Println("ip", ip)

	s.mut.Lock()
	defer s.mut.Unlock()

	listener := NewPassthroughListener()

	s.listenMap[address] = listener

	l := &Listener{
		listener:     listener,
		domain:       s.tunConfig.Domain,
		tunnelConfig: s.tunConfig,
	}

	return l, nil
}
