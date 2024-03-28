package waygate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/anderspitman/omnistreams-go"
	"github.com/mailgun/proxyproto"
	"github.com/waygate-io/waygate-go/josencillo"
	"nhooyr.io/websocket"
)

type OmnistreamsTunnel struct {
	conn      *omnistreams.Connection
	tunConfig *TunnelConfig
}

func (t *OmnistreamsTunnel) OpenStream() (connCloseWriter, error) {
	return t.OpenStreamType(MessageTypeStream)
}

func (t *OmnistreamsTunnel) OpenStreamType(msgType MessageType) (connCloseWriter, error) {
	stream, err := t.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return &omnistreamWrapper{
		msgType:         msgType,
		sendMessageType: true,
		ostream:         stream,
	}, nil
}

func (t *OmnistreamsTunnel) AcceptStream() (connCloseWriter, error) {
	stream, _, err := t.AcceptStreamType()
	return stream, err
}

func (t *OmnistreamsTunnel) AcceptStreamType() (connCloseWriter, MessageType, error) {
	stream, err := t.conn.AcceptStream()
	if err != nil {
		return nil, MessageTypeError, err
	}

	msgType, err := readStreamType(stream)
	if err != nil {
		return nil, MessageTypeError, err
	}

	return &omnistreamWrapper{
		msgType:         msgType,
		sendMessageType: false,
		ostream:         stream,
	}, msgType, nil
}

func (t *OmnistreamsTunnel) SendMessage(msg interface{}) (interface{}, error) {
	return request(t, msg)
}

func (t *OmnistreamsTunnel) ReceiveDatagram() ([]byte, net.Addr, net.Addr, error) {
	msg, err := t.conn.ReceiveMessage()
	if err != nil {
		return nil, nil, nil, err
	}

	reader := bytes.NewReader(msg)

	ppHeader, err := proxyproto.ReadHeader(reader)
	if err != nil {
		return nil, nil, nil, err
	}

	remaining, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, nil, err
	}

	return remaining, ppHeader.Source, ppHeader.Destination, nil
}

func (t *OmnistreamsTunnel) SendDatagram(msg []byte, srcAddr, dstAddr net.Addr) error {

	conn := &wrapperConn{
		localAddr:  dstAddr,
		remoteAddr: srcAddr,
	}

	// TODO: maybe pass addr.IP as serverName?
	proxyHeader, err := buildProxyProtoHeader(conn, "")
	if err != nil {
		return err
	}

	prependedBuf := &bytes.Buffer{}

	_, err = proxyHeader.WriteTo(prependedBuf)
	if err != nil {
		return err
	}

	_, err = prependedBuf.Write(msg)
	if err != nil {
		return err
	}

	return t.conn.SendMessage(prependedBuf.Bytes())
}

func (t *OmnistreamsTunnel) GetConfig() TunnelConfig {
	return *t.tunConfig
}

func (t *OmnistreamsTunnel) Request(req interface{}) (interface{}, error) {
	return request(t, req)
}

func (t *OmnistreamsTunnel) HandleRequests(callback func(interface{}) interface{}) error {
	return handleRequests(t, callback)
}

func NewOmnistreamsServerTunnel(
	w http.ResponseWriter,
	r *http.Request,
	jose *josencillo.JOSE,
	public bool,
	tunnelDomains []string,
) (*OmnistreamsTunnel, error) {

	tunnelReq := TunnelRequest{
		Token:            r.URL.Query().Get("token"),
		TerminationType:  r.URL.Query().Get("termination-type"),
		UseProxyProtocol: r.URL.Query().Get("use-proxy-protocol") == "true",
	}

	tunConfig, err := processRequest(tunnelReq, tunnelDomains, jose, public)
	if err != nil {
		return nil, err
	}

	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return nil, err
	}

	wsConn.SetReadLimit(128 * 1024)

	conn := omnistreams.NewConnection(wsConn, false)

	t := &OmnistreamsTunnel{
		conn:      conn,
		tunConfig: tunConfig,
	}

	_, err = request(t, tunConfig)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func NewOmnistreamsClientTunnel(tunReq TunnelRequest) (*OmnistreamsTunnel, error) {

	ctx := context.Background()

	uri := fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s&use-proxy-protocol=%t",
		WaygateServerDomain,
		tunReq.Token,
		tunReq.TerminationType,
		tunReq.UseProxyProtocol,
	)

	wsConn, _, err := websocket.Dial(ctx, uri, nil)
	if err != nil {
		return nil, err
	}

	conn := omnistreams.NewConnection(wsConn, true)

	tunConfigStream, err := conn.AcceptStream()
	if err != nil {
		return nil, err
	}

	msgTypeBuf := make([]byte, 1)
	_, err = tunConfigStream.Read(msgTypeBuf)
	if err != nil {
		return nil, err
	}

	msgType := MessageType(msgTypeBuf[0])

	if msgType != MessageTypeTunnelConfig {
		return nil, errors.New("Expected MessageTypeTunnelConfig")
	}

	var tunConfig TunnelConfig

	tunConfigBytes, err := io.ReadAll(tunConfigStream)
	if err != nil {
		return nil, err
	}

	if len(tunConfigBytes) == 0 {
		return nil, errors.New("No tunnel config received")
	}

	err = json.Unmarshal(tunConfigBytes, &tunConfig)
	if err != nil {
		return nil, err
	}

	msgTypeBuf[0] = byte(MessageTypeSuccess)
	_, err = tunConfigStream.Write(msgTypeBuf)
	if err != nil {
		return nil, err
	}

	err = tunConfigStream.CloseWrite()
	if err != nil {
		return nil, err
	}

	t := &OmnistreamsTunnel{
		conn:      conn,
		tunConfig: &tunConfig,
	}

	return t, nil
}

type omnistreamWrapper struct {
	msgType         MessageType
	sendMessageType bool
	ostream         *omnistreams.Stream
}

func goid() int {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	id, err := strconv.Atoi(idField)
	if err != nil {
		panic(fmt.Sprintf("cannot get goroutine id: %v", err))
	}
	return id
}

func (w *omnistreamWrapper) Read(buf []byte) (int, error) {

	n, err := w.ostream.Read(buf)

	return n, err
}
func (w *omnistreamWrapper) Write(buf []byte) (int, error) {
	if w.sendMessageType {
		w.sendMessageType = false

		err := streamFirstWrite(w.ostream, buf, w.msgType)
		if err != nil {
			return len(buf), err
		}

		return len(buf), nil
	}

	return w.ostream.Write(buf)
}
func (w *omnistreamWrapper) Close() error {
	return w.ostream.Close()
}
func (w *omnistreamWrapper) CloseWrite() error {
	return w.ostream.CloseWrite()
}
func (w *omnistreamWrapper) LocalAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("omnistreams-network-%d", w.ostream.StreamID()),
		address: fmt.Sprintf("omnistreams-address-%d", w.ostream.StreamID()),
	}
}
func (w *omnistreamWrapper) RemoteAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("omnistreams-network-%d", w.ostream.StreamID()),
		address: fmt.Sprintf("omnistreams-address-%d", w.ostream.StreamID()),
	}
}
func (w *omnistreamWrapper) SetDeadline(t time.Time) error {
	return errors.New("SetDeadline not implemented")
}
func (w *omnistreamWrapper) SetReadDeadline(t time.Time) error {
	return errors.New("SetReadDeadline not implemented")
}
func (w *omnistreamWrapper) SetWriteDeadline(t time.Time) error {
	return errors.New("SetWriteDeadline not implemented")
}
