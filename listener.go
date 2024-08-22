package waygate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/mailgun/proxyproto"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const PROXY_PROTO_PP2_TYPE_MIN_CUSTOM = 0xe0
const PROXY_PROTO_SERVER_NAME_OFFSET = PROXY_PROTO_PP2_TYPE_MIN_CUSTOM + 0
const ListenerDefaultKey = "default-listener"

type Listener struct {
	listener *PassthroughListener
	tunnel   Tunnel
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
func (l *Listener) GetTunnelConfig() TunnelConfig {
	return l.tunnel.GetConfig()
}
func DialUDP(network string, udpAddr *net.UDPAddr) (*UDPConn, error) {
	s, err := NewClientSession(DefaultToken, DefaultCertDir)
	if err != nil {
		return nil, err
	}

	return s.DialUDP(network, udpAddr)
}
func ListenUDP(network string, udpAddr *net.UDPAddr) (*UDPConn, error) {

	//address := fmt.Sprintf("%s:%d", udpAddr.IP, udpAddr.Port)

	s, err := NewClientSession(DefaultToken, DefaultCertDir)
	if err != nil {
		return nil, err
	}

	return s.ListenUDP(network, udpAddr)
}
func Listen(network, address string) (*Listener, error) {
	return ListenWithOpts(network, address, DefaultToken, DefaultCertDir)
}
func ListenWithOpts(network, address, token, certDir string) (*Listener, error) {

	s, err := NewClientSession(token, certDir)
	if err != nil {
		return nil, err
	}

	return s.Listen(network, address)
}

type ClientSession struct {
	tunnel Tunnel
	//tunnel         *WebTransportTunnel
	tlsConfig      *tls.Config
	tlsTermination string
	listenMap      map[string]*PassthroughListener
	udpMap         map[string]*UDPConn
	mut            *sync.Mutex
	logger         *zap.Logger
}

func NewClientSession(token, certDir string) (*ClientSession, error) {

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
		return nil, err
	}

	certmagic.DefaultACME.DisableHTTPChallenge = true

	certmagic.DefaultACME.Agreed = true
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	var s *ClientSession

	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(ctx context.Context, name string) error {
			if s != nil {
				if !strings.HasSuffix(name, s.tunnel.GetConfig().Domain) {
					return fmt.Errorf("not allowed")
				}
			}
			return nil
		},
	}

	certmagic.Default.Storage = &certmagic.FileStorage{certDir}

	var output zapcore.WriteSyncer = os.Stdout
	logOutput := zapcore.Lock(output)
	logEncoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	logPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.InfoLevel
	})

	logCore := zapcore.NewCore(logEncoder, logOutput, logPriority)

	logger := zap.New(logCore)

	certmagic.Default.Logger = logger
	certmagic.DefaultACME.Logger = logger

	certConfig := certmagic.NewDefault()

	//ctx := context.Background()

	tlsConfig := &tls.Config{
		GetCertificate: certConfig.GetCertificate,
		//NextProtos:     []string{"h2", "acme-tls/1"},
		// TODO: re-enable h2 support, probably by proxying at the HTTP level
		NextProtos: []string{"http/1.1", "acme-tls/1"},
	}

	tunReq := TunnelRequest{
		Token:           token,
		TerminationType: "client",
		//TerminationType:  "server",
		UseProxyProtocol: true,
	}

	tunnel, err := NewOmnistreamsClientTunnel(tunReq)
	//tunnel, err := NewWebTransportClientTunnel(tunReq)
	//tunnel, err := NewTlsMuxadoClientTunnel(tunReq)
	//tunnel, err := NewWebSocketMuxadoClientTunnel(tunReq)
	if err != nil {
		return nil, err
	}

	s = &ClientSession{
		tunnel:         tunnel,
		tlsConfig:      tlsConfig,
		tlsTermination: tunnel.GetConfig().TerminationType,
		listenMap:      make(map[string]*PassthroughListener),
		udpMap:         make(map[string]*UDPConn),
		mut:            &sync.Mutex{},
		logger:         logger,
	}

	s.start()

	return s, nil
}

func (s *ClientSession) start() {

	go func() {
		for {
			dgram, _, dstAddr, err := s.tunnel.ReceiveDatagram()
			if err != nil {
				fmt.Println("ClientSession.start ReceiveDatagram:", err)
				break
			}

			//dst := fmt.Sprintf("%s:%d", dstAddr.IP, dstAddr.Port)

			udpConn, ok := s.udpMap[dstAddr.String()]
			if !ok {
				fmt.Println("ClientSession.start udpMap: no such UDPConn")
				break
			}

			udpConn.recvCh <- dgram
		}
	}()

	go func() {

		defer s.logger.Sync()

		for {
			downstreamConn, err := s.tunnel.AcceptStream()
			if err != nil {
				log.Println("ClientSession.start AcceptStream:", err)
				break
			}

			go func() {

				var conn connCloseWriter = downstreamConn

				serverName := ""
				remoteAddress := "dummy-address:0"
				localAddress := "dummy-address:0"
				if s.tunnel.GetConfig().UseProxyProtocol {
					ppHeader, err := proxyproto.ReadHeader(conn)
					if err != nil {
						log.Println(err)
						return
					}

					remoteAddress = ppHeader.Source.String()
					localAddress = ppHeader.Destination.String()

					tlvs, err := ppHeader.ParseTLVs()
					if err != nil {
						log.Println(err)
						return
					}

					serverName = string(tlvs[PROXY_PROTO_SERVER_NAME_OFFSET])
				}

				// TODO: figure out a cleaner way to disable TLS for raw TCP.
				// TerminationType should probably be a per-listen setting, instead
				// of per-tunnel
				if s.tlsTermination == "client" && serverName != "" {
					tlsConn := tls.Server(conn, s.tlsConfig)
					err := tlsConn.Handshake()
					if err != nil {
						fmt.Println("fatal fail", err)
						return
					}
					conn = tlsConn
				}

				conn = wrapperConn{
					conn: conn,
					localAddr: addr{
						network: "waygate-network",
						address: localAddress,
					},
					remoteAddr: addr{
						network: "waygate-network",
						address: remoteAddress,
					},
				}

				s.mut.Lock()
				defer s.mut.Unlock()

				_, portStr, err := net.SplitHostPort(localAddress)
				if err != nil {
					log.Println("Error splitting address")
					return
				}

				port, err := strconv.Atoi(portStr)
				if err != nil {
					log.Println("Error parsing port")
					return
				}

				key := serverName
				if key == "" {
					key = fmt.Sprintf(":%d", port)
				}

				listener, exists := s.listenMap[key]
				if !exists {
					listener, exists = s.listenMap[ListenerDefaultKey]
					if !exists {
						fmt.Println("No such listener", key)
						conn.Close()
						return
					}
				}

				listener.PassConn(conn)
			}()
		}
	}()
}

func (s *ClientSession) GetTunnelConfig() TunnelConfig {
	return s.tunnel.GetConfig()
}

func (s *ClientSession) DialUDP(network string, dstAddr *net.UDPAddr) (*UDPConn, error) {

	address := fmt.Sprintf("%s:%d", dstAddr.IP, dstAddr.Port)

	req := &DialRequest{
		Network: network,
		Address: address,
	}

	res, err := s.tunnel.Request(req)
	if err != nil {
		return nil, err
	}

	dialRes := res.(*DialResponse)

	if !dialRes.Success {
		return nil, errors.New(dialRes.Message)
	}

	srcAddr, err := net.ResolveUDPAddr("udp", dialRes.Address)
	if err != nil {
		return nil, err
	}

	conn := &UDPConn{
		recvCh: make(chan []byte),
		sendCh: make(chan []byte),
	}

	go func() {
		for {
			msg := <-conn.sendCh
			s.tunnel.SendDatagram(msg, srcAddr, dstAddr)
		}
	}()

	s.mut.Lock()
	s.udpMap[dialRes.Address] = conn
	s.mut.Unlock()

	printJson(s.udpMap)

	return conn, nil
}

func (s *ClientSession) ListenUDP(network string, udpAddr *net.UDPAddr) (*UDPConn, error) {

	address := fmt.Sprintf("%s:%d", udpAddr.IP, udpAddr.Port)

	listenReq := &ListenRequest{
		Network: network,
		Address: address,
	}

	listenRes, err := s.tunnel.Request(listenReq)
	if err != nil {
		return nil, err
	}

	lres := listenRes.(*ListenResponse)

	printJson(lres)

	c := &UDPConn{
		recvCh: make(chan []byte),
	}

	s.mut.Lock()
	s.udpMap[address] = c
	s.mut.Unlock()

	return c, nil
}

func (s *ClientSession) Listen(network, address string) (*Listener, error) {

	if network != "tcp" && network != "tcp4" && network != "udp" {
		return nil, errors.New(fmt.Sprintf("Invalid network type: %s", network))
	}

	if address == "" {
		address = ListenerDefaultKey
	} else {
		listenReq := &ListenRequest{
			Network: network,
			Address: address,
		}

		listenRes, err := s.tunnel.Request(listenReq)
		if err != nil {
			return nil, err
		}

		lres := listenRes.(*ListenResponse)

		printJson(lres)
	}

	//ip := net.ParseIP(address)

	s.mut.Lock()
	defer s.mut.Unlock()

	listener := NewPassthroughListener()

	s.listenMap[address] = listener

	l := &Listener{
		listener: listener,
		tunnel:   s.tunnel,
	}

	return l, nil
}

type UDPConn struct {
	recvCh chan []byte
	sendCh chan []byte
}

func (c *UDPConn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	msg := <-c.recvCh
	if len(msg) > len(buf) {
		return 0, nil, errors.New("UDPConn.ReadFromUDP: buf not big enough")
	}

	n := copy(buf, msg)

	return n, nil, nil
}

func (c *UDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {

	buf := make([]byte, len(p))

	copy(buf, p)

	c.sendCh <- buf

	return len(p), nil
}
