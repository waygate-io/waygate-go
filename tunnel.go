package waygate

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/webtransport-go"
	"github.com/waygate-io/waygate-go/josencillo"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

const WebTransportCodeCancel = 0

type Tunnel interface {
	OpenStream() (connCloseWriter, error)
	AcceptStream() (connCloseWriter, error)
	GetConfig() TunnelConfig
}

type MuxadoTunnel struct {
	muxSess   muxado.Session
	tunConfig TunnelConfig
}

func (t *MuxadoTunnel) OpenStream() (connCloseWriter, error) {
	return t.muxSess.OpenStream()
}

func (t *MuxadoTunnel) AcceptStream() (connCloseWriter, error) {
	return t.muxSess.AcceptStream()
}

func (t *MuxadoTunnel) GetConfig() TunnelConfig {
	return t.tunConfig
}

type WebTransportTunnel struct {
	tunConfig TunnelConfig
	wtSession *webtransport.Session
	ctx       context.Context
}

func (t *WebTransportTunnel) OpenStream() (connCloseWriter, error) {
	stream, err := t.wtSession.OpenStreamSync(t.ctx)
	if err != nil {
		return nil, err
	}

	return wtStreamWrapper{
		wtStream: stream,
	}, nil
}

func (t *WebTransportTunnel) AcceptStream() (connCloseWriter, error) {
	stream, err := t.wtSession.AcceptStream(t.ctx)
	if err != nil {
		return nil, err
	}

	return wtStreamWrapper{
		wtStream: stream,
	}, nil
}

func NewTlsMuxadoServerTunnel(tlsConn *tls.Conn, jose *josencillo.JOSE, public bool) (*MuxadoTunnel, error) {
	msgSizeBuf := make([]byte, 4)

	_, err := tlsConn.Read(msgSizeBuf)
	if err != nil {
		return nil, err
	}

	setupReqSize := binary.BigEndian.Uint32(msgSizeBuf)

	setupReqBuf := make([]byte, setupReqSize)

	_, err = tlsConn.Read(setupReqBuf)
	if err != nil {
		log.Println("Error reading setup size", err)
		return nil, err
	}

	var tunnelReq TunnelRequest

	err = json.Unmarshal(setupReqBuf, &tunnelReq)
	if err != nil {
		return nil, err
	}

	tokenJwt := tunnelReq.Token
	if tokenJwt == "" {
		return nil, err
	}

	domain, err := genRandomText(8)
	if err != nil {
		return nil, err
	}

	if !public {
		claims, err := jose.ParseJWT(tokenJwt)
		if err != nil {
			return nil, err
		}

		domain = claims["domain"].(string)
	}

	tunConfig := TunnelConfig{
		Domain:           domain,
		TerminationType:  tunnelReq.TerminationType,
		UseProxyProtocol: tunnelReq.UseProxyProtocol,
	}

	setupResBytes, err := json.Marshal(tunConfig)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint32(msgSizeBuf, uint32(len(setupResBytes)))

	_, err = tlsConn.Write(msgSizeBuf)
	if err != nil {
		return nil, err
	}

	_, err = tlsConn.Write(setupResBytes)
	if err != nil {
		return nil, err
	}

	muxSess := muxado.Server(tlsConn, &muxado.Config{
		MaxWindowSize: 1 * 1024 * 1024,
	})

	t := &MuxadoTunnel{
		muxSess:   muxSess,
		tunConfig: tunConfig,
	}

	return t, nil
}

func NewWebSocketMuxadoServerTunnel(
	w http.ResponseWriter,
	r *http.Request,
	jose *josencillo.JOSE,
	public bool,
	tunnelDomains []string,
) (*MuxadoTunnel, error) {

	tunnelReq := TunnelRequest{
		Token:            r.URL.Query().Get("token"),
		TerminationType:  r.URL.Query().Get("termination-type"),
		UseProxyProtocol: r.URL.Query().Get("use-proxy-protocol") == "true",
	}

	tunConfig, err := processRequest(tunnelReq, tunnelDomains, jose, public)
	if err != nil {
		return nil, err
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return nil, err
	}

	bytes, err := json.Marshal(tunConfig)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	err = c.Write(ctx, websocket.MessageBinary, bytes)
	if err != nil {
		return nil, err
	}

	sessConn := websocket.NetConn(ctx, c, websocket.MessageBinary)

	muxSess := muxado.Server(sessConn, &muxado.Config{
		MaxWindowSize: 1 * 1024 * 1024,
	})

	t := &MuxadoTunnel{
		muxSess:   muxSess,
		tunConfig: *tunConfig,
	}

	return t, nil
}

func NewWebTransportServerTunnel(
	w http.ResponseWriter,
	r *http.Request,
	wtServer webtransport.Server,
	jose *josencillo.JOSE,
	public bool,
	tunnelDomains []string,
) (*WebTransportTunnel, error) {

	ctx := context.Background()

	wtSession, err := wtServer.Upgrade(w, r)
	if err != nil {
		return nil, err
	}

	wtStream, err := wtSession.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}

	setupStream := wtStreamWrapper{
		wtStream: wtStream,
	}

	tunConfig, err := serverHandshake(setupStream, jose, public, tunnelDomains)
	if err != nil {
		return nil, err
	}

	t := &WebTransportTunnel{
		ctx:       ctx,
		wtSession: wtSession,
		tunConfig: *tunConfig,
	}

	return t, nil
}

func serverHandshake(
	setupStream connCloseWriter,
	jose *josencillo.JOSE,
	public bool,
	tunnelDomains []string,
) (*TunnelConfig, error) {

	setupBytes, err := io.ReadAll(setupStream)
	if err != nil {
		return nil, closeWithError(setupStream, err)
	}

	var tunnelReq TunnelRequest

	err = json.Unmarshal(setupBytes, &tunnelReq)
	if err != nil {
		return nil, err
	}

	tunConfig, err := processRequest(tunnelReq, tunnelDomains, jose, public)
	if err != nil {
		return nil, closeWithError(setupStream, err)
	}

	setupResBytes, err := json.Marshal(tunConfig)
	if err != nil {
		return nil, err
	}

	_, err = setupStream.Write(setupResBytes)
	if err != nil {
		return nil, err
	}

	err = setupStream.CloseWrite()
	if err != nil {
		return nil, err
	}

	return tunConfig, nil
}

func processRequest(tunnelReq TunnelRequest, tunnelDomains []string, jose *josencillo.JOSE, public bool) (*TunnelConfig, error) {

	host, err := genRandomText(8)
	if err != nil {
		return nil, err
	}

	if len(tunnelDomains) == 0 {
		return nil, errors.New("No tunnel domains")
	}

	var domain string
	if tunnelReq.Token == "" {
		if !public {
			return nil, errors.New("No token provided")
		}

		domain = strings.ToLower(host) + "." + tunnelDomains[0]
	} else {
		claims, err := jose.ParseJWT(tunnelReq.Token)
		if err != nil {
			return nil, err
		}

		domain = claims["domain"].(string)
	}

	tunConfig := &TunnelConfig{
		Domain:           domain,
		TerminationType:  tunnelReq.TerminationType,
		UseProxyProtocol: tunnelReq.UseProxyProtocol,
	}

	return tunConfig, nil
}

func NewTlsMuxadoClientTunnel(tunnelReq TunnelRequest) (*MuxadoTunnel, error) {

	tlsDialConfig := &tls.Config{
		//NextProtos: []string{"waygate-tls-muxado", "http/1.1"},
		NextProtos: []string{"waygate-tls-muxado"},
	}

	tlsConn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", WaygateServerDomain), tlsDialConfig)
	if err != nil {
		return nil, err
	}

	setupReqBytes, err := json.Marshal(tunnelReq)
	if err != nil {
		return nil, err
	}

	msgSizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(msgSizeBuf, uint32(len(setupReqBytes)))

	_, err = tlsConn.Write(msgSizeBuf)
	if err != nil {
		return nil, err
	}

	_, err = tlsConn.Write(setupReqBytes)
	if err != nil {
		return nil, err
	}

	_, err = tlsConn.Read(msgSizeBuf)
	if err != nil {
		return nil, err
	}

	setupResSize := binary.BigEndian.Uint32(msgSizeBuf)

	setupResBuf := make([]byte, setupResSize)

	_, err = tlsConn.Read(setupResBuf)
	if err != nil {
		return nil, err
	}

	var tunConfig TunnelConfig

	err = json.Unmarshal(setupResBuf, &tunConfig)
	if err != nil {
		return nil, err
	}

	muxSess := muxado.Client(tlsConn, &muxado.Config{
		MaxWindowSize: 1 * 1024 * 1024,
	})

	t := &MuxadoTunnel{
		muxSess:   muxSess,
		tunConfig: tunConfig,
	}

	return t, err
}

func NewWebSocketMuxadoClientTunnel(tunReq TunnelRequest) (*MuxadoTunnel, error) {

	ctx := context.Background()

	uri := fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s&use-proxy-protocol=%s",
		WaygateServerDomain,
		tunReq.Token,
		tunReq.TerminationType,
		tunReq.UseProxyProtocol,
	)

	wsConn, _, err := websocket.Dial(ctx, uri, nil)
	if err != nil {
		return nil, err
	}

	_, tunConfigBytes, err := wsConn.Read(ctx)
	if err != nil {
		return nil, err
	}

	var tunConfig TunnelConfig

	err = json.Unmarshal(tunConfigBytes, &tunConfig)
	if err != nil {
		return nil, err
	}

	sessConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	muxSess := muxado.Client(sessConn, &muxado.Config{
		MaxWindowSize: 1 * 1024 * 1024,
	})

	t := &MuxadoTunnel{
		muxSess:   muxSess,
		tunConfig: tunConfig,
	}

	return t, nil
}

func NewWebTransportClientTunnel(tunnelReq TunnelRequest) (Tunnel, error) {

	uri := fmt.Sprintf("https://%s/waygate", WaygateServerDomain)

	ctx := context.Background()

	var d webtransport.Dialer
	_, wtSession, err := d.Dial(ctx, uri, nil)
	if err != nil {
		return nil, err
	}

	setupStream, err := wtSession.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	setupReqBytes, err := json.Marshal(tunnelReq)
	if err != nil {
		return nil, err
	}

	_, err = setupStream.Write(setupReqBytes)
	if err != nil {
		return nil, err
	}

	err = setupStream.Close()
	if err != nil {
		return nil, err
	}

	setupResBytes, err := io.ReadAll(setupStream)
	if err != nil {
		return nil, err
	}

	var tunConfig TunnelConfig

	err = json.Unmarshal(setupResBytes, &tunConfig)
	if err != nil {
		return nil, err
	}

	t := &WebTransportTunnel{
		ctx:       ctx,
		wtSession: wtSession,
		tunConfig: tunConfig,
	}

	return t, nil
}

func (t *WebTransportTunnel) GetConfig() TunnelConfig {
	return t.tunConfig
}

type wtStreamWrapper struct {
	wtStream webtransport.Stream
}

func (w wtStreamWrapper) Read(buf []byte) (int, error) {
	return w.wtStream.Read(buf)
}
func (w wtStreamWrapper) Write(buf []byte) (int, error) {
	return w.wtStream.Write(buf)
}
func (w wtStreamWrapper) Close() error {
	// quic.Stream.Close only closes the write side, see here:
	// https://pkg.go.dev/github.com/quic-go/quic-go#readme-using-streams
	w.wtStream.CancelRead(WebTransportCodeCancel)
	w.wtStream.CancelWrite(WebTransportCodeCancel)
	return nil
}
func (w wtStreamWrapper) CloseWrite() error {
	// quic.Stream.Close only closes the write side, see here:
	// https://pkg.go.dev/github.com/quic-go/quic-go#readme-using-streams
	return w.wtStream.Close()
}
func (w wtStreamWrapper) LocalAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("webtransport-network-%d", w.wtStream.StreamID()),
		address: fmt.Sprintf("webtransport-address-%d", w.wtStream.StreamID()),
	}
}
func (w wtStreamWrapper) RemoteAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("webtransport-network-%d", w.wtStream.StreamID()),
		address: fmt.Sprintf("webtransport-address-%d", w.wtStream.StreamID()),
	}
}
func (w wtStreamWrapper) SetDeadline(t time.Time) error {
	return w.wtStream.SetDeadline(t)
}
func (w wtStreamWrapper) SetReadDeadline(t time.Time) error {
	return w.wtStream.SetReadDeadline(t)
}
func (w wtStreamWrapper) SetWriteDeadline(t time.Time) error {
	return w.wtStream.SetWriteDeadline(t)
}

const MessageTypeError = 0

type ErrorMessage struct {
	Type    int    `json:"type"`
	Message string `json:"message"`
}

func closeWithError(stream connCloseWriter, inErr error) error {
	// TODO: maybe need to close
	//defer stream.Close()

	e := ErrorMessage{
		Type:    MessageTypeError,
		Message: inErr.Error(),
	}

	errBytes, err := json.Marshal(e)
	if err != nil {
		return err
	}

	_, err = stream.Write(errBytes)
	if err != nil {
		return err
	}

	return inErr
}
