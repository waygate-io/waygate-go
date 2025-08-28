package waygate

import (
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
	omnitransport "github.com/omnistreams/omnistreams-go/transports"
)

const PROXY_PROTO_PP2_TYPE_MIN_CUSTOM = 0xe0
const PROXY_PROTO_SERVER_NAME_OFFSET = PROXY_PROTO_PP2_TYPE_MIN_CUSTOM + 0
const ListenerDefaultKey = "default-listener"

type ClientSession struct {
	tunnel Tunnel
	//tunnel         *WebTransportTunnel
	tlsConfig      *tls.Config
	tlsTermination string
	listenMap      map[string]*Listener
	udpMap         map[string]*UDPConn
	mut            *sync.Mutex
}

func NewClientSession(token string, db *ClientDatabase, certConfig *certmagic.Config, terminationType TerminationType) (*ClientSession, error) {

	var s *ClientSession

	var err error

	clientName, err := db.GetClientName()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			//fmt.Println("GetCertificate")
			return certConfig.GetCertificate(ch)
		},
		//NextProtos:     []string{"h2", "acme-tls/1"},
		// TODO: re-enable h2 support, probably by proxying at the HTTP level
		NextProtos: []string{"http/1.1", "acme-tls/1"},
	}

	tunReq := TunnelRequest{
		Token:            token,
		TerminationType:  string(terminationType),
		UseProxyProtocol: true,
		ClientName:       clientName,
	}

	tunnel, err := NewOmnistreamsClientTunnel(tunReq)
	//tunnel, err := NewWebTransportClientTunnel(tunReq)
	//tunnel, err := NewTlsMuxadoClientTunnel(tunReq)
	//tunnel, err := NewWebSocketMuxadoClientTunnel(tunReq)
	if authErr, ok := err.(*omnitransport.AuthenticationError); ok {
		// TODO: feels hacky.
		// Probably a bad token. Reset it which will force re-auth
		db.SetToken("")
		return nil, authErr
	} else if err != nil {
		return nil, err
	}

	domain := tunnel.GetConfig().Domain

	err = db.SetDomain(Domain{
		Domain: domain,
		Status: DomainStatusPending,
	})
	if err != nil {
		return nil, err
	}

	s = &ClientSession{
		tunnel:         tunnel,
		tlsConfig:      tlsConfig,
		tlsTermination: tunnel.GetConfig().TerminationType,
		listenMap:      make(map[string]*Listener),
		udpMap:         make(map[string]*UDPConn),
		mut:            &sync.Mutex{},
	}

	s.start()

	return s, nil
}

func (s *ClientSession) start() {

	go func() {

		for {
			msg, srcAddr, dstAddr, err := s.tunnel.ReceiveDatagram()
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

			srcUDPAddr, err := net.ResolveUDPAddr("udp", srcAddr.String())
			if err != nil {
				fmt.Println("ClientSession.start ResolveUDPAddr:", err)
				break
			}

			dstUDPAddr, err := net.ResolveUDPAddr("udp", dstAddr.String())
			if err != nil {
				fmt.Println("ClientSession.start ResolveUDPAddr:", err)
				break
			}

			udpConn.recvCh <- datagram{
				msg:     msg,
				srcAddr: srcUDPAddr,
				dstAddr: dstUDPAddr,
			}
		}

	}()

	go func() {

		for {
			downstreamConn, err := s.tunnel.AcceptStream()
			if err != nil {
				log.Println("ClientSession.start AcceptStream:", err)
				break
			}

			go func() {
				s.handleStream(downstreamConn)
			}()
		}

		os.Exit(64)
	}()
}

func (s *ClientSession) handleStream(downstreamConn connCloseWriter) {

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
		key = fmt.Sprintf("0.0.0.0:%d", port)
	}

	s.mut.Lock()
	listener, exists := s.listenMap[key]
	s.mut.Unlock()
	if !exists {
		s.mut.Lock()
		listener, exists = s.listenMap[ListenerDefaultKey]
		s.mut.Unlock()
		if !exists {
			fmt.Println("No such listener", key)
			conn.Close()
			return
		}
	}

	// TODO: figure out a cleaner way to disable TLS for raw TCP.
	// TerminationType should probably be a per-listen setting, instead
	// of per-tunnel
	// TODO: still some stuff here that might should be mutexed
	if s.tlsTermination == TerminationTypeClient && !listener.tlsPassthrough && serverName != "" {
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

	listener.listener.PassConn(conn)
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
		recvCh: make(chan datagram),
		sendCh: make(chan datagram),
	}

	go func() {
		for {
			datagram := <-conn.sendCh
			s.tunnel.SendDatagram(datagram.msg, srcAddr, dstAddr)
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

	localAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	c := &UDPConn{
		recvCh:    make(chan datagram),
		sendCh:    make(chan datagram),
		localAddr: localAddr,
	}

	s.mut.Lock()
	s.udpMap[address] = c
	s.mut.Unlock()

	go func() {
		for {
			dgram := <-c.sendCh
			// TODO: should probably use the conn localAddr here
			err := s.tunnel.SendDatagram(dgram.msg, dgram.srcAddr, dgram.dstAddr)
			if err != nil {
				fmt.Println(err)
				continue
			}
		}
	}()

	return c, nil
}

func (s *ClientSession) Listen(network, address string) (*Listener, error) {

	if network != "tls" && network != "tcp" && network != "tcp4" && network != "udp" {
		return nil, errors.New(fmt.Sprintf("Invalid network type: %s", network))
	}

	tlsPassthrough := false
	// TODO: handle IPv6
	addrParts := strings.Split(address, ":")
	// If a TCP tunnel is requested but no port is provided, assume it's
	// a TLS connection but we should not decrypt, ie we should pass
	// through the raw TCP stream.
	if network == "tcp" && len(addrParts) != 2 && address != ListenerDefaultKey {
		tlsPassthrough = true
		network = "tls"
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

	l := &Listener{
		listener:       listener,
		tunnel:         s.tunnel,
		tlsPassthrough: tlsPassthrough,
	}

	s.listenMap[address] = l

	return l, nil
}

type ListenOptions struct {
	Token string
	Db    *ClientDatabase
}

type Listener struct {
	listener       *PassthroughListener
	tunnel         Tunnel
	tlsPassthrough bool
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

//func DialUDP(network string, udpAddr *net.UDPAddr) (*UDPConn, error) {
//	s, err := NewClientSession(DefaultToken, nil, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	return s.DialUDP(network, udpAddr)
//}
//func ListenUDP(network string, udpAddr *net.UDPAddr) (*UDPConn, error) {
//
//	//address := fmt.Sprintf("%s:%d", udpAddr.IP, udpAddr.Port)
//
//	s, err := NewClientSession(DefaultToken, nil, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	return s.ListenUDP(network, udpAddr)
//}
//func Listen(network, address string, opts ...ListenOptions) (*Listener, error) {
//
//	token := DefaultToken
//	var db *ClientDatabase
//
//	if len(opts) > 0 {
//		token = opts[0].Token
//		db = opts[0].Db
//	}
//
//	s, err := NewClientSession(token, db, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	return s.Listen(network, address)
//}
//func ListenWithOpts(network, address, token string, db *ClientDatabase) (*Listener, error) {
//
//	s, err := NewClientSession(token, db, nil)
//	if err != nil {
//		return nil, err
//	}
//
//	return s.Listen(network, address)
//}

type UDPConn struct {
	recvCh    chan datagram
	sendCh    chan datagram
	localAddr *net.UDPAddr
}

func (c *UDPConn) ReadFromUDP(buf []byte) (int, *net.UDPAddr, error) {
	dgram := <-c.recvCh
	if len(dgram.msg) > len(buf) {
		return 0, nil, errors.New("UDPConn.ReadFromUDP: buf not big enough")
	}

	n := copy(buf, dgram.msg)

	return n, dgram.srcAddr, nil
}

func (c *UDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (int, error) {

	buf := make([]byte, len(p))

	copy(buf, p)

	c.sendCh <- datagram{
		msg:     buf,
		srcAddr: c.localAddr,
		dstAddr: addr,
	}

	return len(p), nil
}

type datagram struct {
	msg     []byte
	srcAddr *net.UDPAddr
	dstAddr *net.UDPAddr
}
