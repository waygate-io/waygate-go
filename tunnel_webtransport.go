package waygate

import (
	"context"
	//"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/webtransport-go"
	"github.com/waygate-io/waygate-go/josencillo"
	"github.com/lastlogin-net/decent-auth-go"
)

const WebTransportCodeCancel = 0

type WebTransportTunnel struct {
	tunConfig     TunnelConfig
	controlStream connCloseWriter
	wtSession     *webtransport.Session
	ctx           context.Context
}

func (t *WebTransportTunnel) Request(req interface{}) (interface{}, error) {
	return request(t, req)
}

func (t *WebTransportTunnel) HandleRequests(callback func(interface{}) interface{}) error {
	return handleRequests(t, callback)
}

func (t *WebTransportTunnel) ReceiveDatagram() ([]byte, net.Addr, net.Addr, error) {
	time.Sleep(10 * time.Second)
	return nil, nil, nil, errors.New("WebTransportTunnel.ReceiveDatagram not implemented")
}

func (t *WebTransportTunnel) SendDatagram(msg []byte, srcAddr, dstAdd net.Addr) error {
	time.Sleep(10 * time.Second)
	return errors.New("WebTransportTunnel.SendDatagram not implemented")
}

func (t *WebTransportTunnel) OpenStream() (connCloseWriter, error) {
	return t.OpenStreamType(MessageTypeStream)
}

func (t *WebTransportTunnel) OpenStreamType(msgType MessageType) (connCloseWriter, error) {
	stream, err := t.wtSession.OpenStreamSync(t.ctx)
	if err != nil {
		return nil, err
	}

	return &wtStreamWrapper{
		msgType:         msgType,
		sendMessageType: true,
		wtStream:        stream,
	}, nil
}

func (t *WebTransportTunnel) AcceptStream() (connCloseWriter, error) {
	stream, _, err := t.AcceptStreamType()
	return stream, err
}

func (t *WebTransportTunnel) AcceptStreamType() (connCloseWriter, MessageType, error) {

	stream, err := t.wtSession.AcceptStream(t.ctx)
	if err != nil {
		return nil, MessageTypeError, err
	}

	msgType, err := readStreamType(stream)
	if err != nil {
		return nil, MessageTypeError, err
	}

	return &wtStreamWrapper{
		msgType:         msgType,
		sendMessageType: false,
		wtStream:        stream,
	}, msgType, nil
}

func (t *WebTransportTunnel) Events() chan TunnelEvent {
	return nil
}

func NewWebTransportServerTunnel(
	w http.ResponseWriter,
	r *http.Request,
	wtServer webtransport.Server,
	jose *josencillo.JOSE,
	authServer *decentauth.Handler,
	public bool,
	tunnelDomains []string,
) (*WebTransportTunnel, error) {

	tunnelReq := TunnelRequest{
		Token:            r.URL.Query().Get("token"),
		TerminationType:  r.URL.Query().Get("termination-type"),
		UseProxyProtocol: r.URL.Query().Get("use-proxy-protocol") == "true",
	}

	session := authServer.GetSession(r)

	tunConfig, err := processRequest(tunnelReq, tunnelDomains, jose, session, public)
	if err != nil {
		return nil, err
	}

	wtSession, err := wtServer.Upgrade(w, r)
	if err != nil {
		return nil, err
	}

	t := &WebTransportTunnel{
		ctx:       context.Background(),
		wtSession: wtSession,
		tunConfig: *tunConfig,
	}

	_, err = request(t, tunConfig)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func NewWebTransportClientTunnel(tunnelReq TunnelRequest) (*WebTransportTunnel, error) {

	return nil, errors.New("NewWebTransportClientTunnel: Not implemented")

	//uri := fmt.Sprintf("https://%s/waygate", WaygateServerDomain)

	//ctx := context.Background()

	//var d webtransport.Dialer
	//_, wtSession, err := d.Dial(ctx, uri, nil)
	//if err != nil {
	//	return nil, err
	//}

	//wtStream, err := wtSession.OpenStreamSync(ctx)
	//if err != nil {
	//	return nil, err
	//}

	//controlStream := &wtStreamWrapper{
	//	wtStream: wtStream,
	//}

	//setupReqBytes, err := json.Marshal(tunnelReq)
	//if err != nil {
	//	return nil, err
	//}

	//err = sendMessage(controlStream, setupReqBytes)
	//if err != nil {
	//	return nil, err
	//}

	//setupResBytes, err := receiveMessage(controlStream)
	//if err != nil {
	//	return nil, err
	//}

	//var tunConfig TunnelConfig

	//err = json.Unmarshal(setupResBytes, &tunConfig)
	//if err != nil {
	//	return nil, err
	//}

	//t := &WebTransportTunnel{
	//	ctx:           ctx,
	//	wtSession:     wtSession,
	//	controlStream: controlStream,
	//	tunConfig:     tunConfig,
	//}

	//return t, nil
}

func (t *WebTransportTunnel) GetConfig() TunnelConfig {
	return t.tunConfig
}

type wtStreamWrapper struct {
	msgType         MessageType
	sendMessageType bool
	wtStream        webtransport.Stream
}

func (w *wtStreamWrapper) Read(buf []byte) (int, error) {
	return w.wtStream.Read(buf)
}
func (w *wtStreamWrapper) Write(buf []byte) (int, error) {
	if w.sendMessageType {
		w.sendMessageType = false

		err := streamFirstWrite(w.wtStream, buf, w.msgType)
		if err != nil {
			return len(buf), err
		}

		return len(buf), nil
	}

	return w.wtStream.Write(buf)
}
func (w *wtStreamWrapper) Close() error {
	// quic.Stream.Close only closes the write side, see here:
	// https://pkg.go.dev/github.com/quic-go/quic-go#readme-using-streams
	w.wtStream.CancelRead(WebTransportCodeCancel)
	w.wtStream.CancelWrite(WebTransportCodeCancel)
	return nil
}
func (w *wtStreamWrapper) CloseWrite() error {
	// quic.Stream.Close only closes the write side, see here:
	// https://pkg.go.dev/github.com/quic-go/quic-go#readme-using-streams
	return w.wtStream.Close()
}
func (w *wtStreamWrapper) LocalAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("webtransport-network-%d", w.wtStream.StreamID()),
		address: fmt.Sprintf("webtransport-address-%d", w.wtStream.StreamID()),
	}
}
func (w *wtStreamWrapper) RemoteAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("webtransport-network-%d", w.wtStream.StreamID()),
		address: fmt.Sprintf("webtransport-address-%d", w.wtStream.StreamID()),
	}
}
func (w *wtStreamWrapper) SetDeadline(t time.Time) error {
	return w.wtStream.SetDeadline(t)
}
func (w *wtStreamWrapper) SetReadDeadline(t time.Time) error {
	return w.wtStream.SetReadDeadline(t)
}
func (w *wtStreamWrapper) SetWriteDeadline(t time.Time) error {
	return w.wtStream.SetWriteDeadline(t)
}
