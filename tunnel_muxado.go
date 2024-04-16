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
	"time"

	"github.com/waygate-io/waygate-go/josencillo"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type MuxadoTunnel struct {
	muxSess   muxado.Session
	tunConfig TunnelConfig
}

func (t *MuxadoTunnel) OpenStream() (connCloseWriter, error) {
	return t.OpenStreamType(MessageTypeStream)
}

func (t *MuxadoTunnel) OpenStreamType(msgType MessageType) (connCloseWriter, error) {
	stream, err := t.muxSess.OpenStream()
	if err != nil {
		return nil, err
	}

	return &streamWrapper{
		msgType:         msgType,
		sendMessageType: true,
		stream:          stream,
		id:              stream.Id(),
	}, nil
}

func (t *MuxadoTunnel) AcceptStream() (connCloseWriter, error) {
	stream, _, err := t.AcceptStreamType()
	return stream, err
}

func (t *MuxadoTunnel) AcceptStreamType() (connCloseWriter, MessageType, error) {
	stream, err := t.muxSess.AcceptStream()
	if err != nil {
		return nil, MessageTypeError, err
	}

	msgType, err := readStreamType(stream)
	if err != nil {
		return nil, MessageTypeError, err
	}

	return &streamWrapper{
		msgType:         msgType,
		sendMessageType: false,
		stream:          stream,
		id:              stream.Id(),
	}, msgType, nil
}

func (t *MuxadoTunnel) ReceiveDatagram() ([]byte, net.Addr, net.Addr, error) {
	time.Sleep(10 * time.Second)
	return nil, nil, nil, errors.New("ReceiveDatagram not implemented")
}

func (t *MuxadoTunnel) SendDatagram(msg []byte, srcAddr, dstAddr net.Addr) error {
	time.Sleep(10 * time.Second)
	return errors.New("SendDatagram not implemented")
}

func (t *MuxadoTunnel) Request(req interface{}) (interface{}, error) {
	return request(t, req)
}

func (t *MuxadoTunnel) HandleRequests(callback func(interface{}) interface{}) error {
	return handleRequests(t, callback)
}

func (t *MuxadoTunnel) GetConfig() TunnelConfig {
	return t.tunConfig
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

	ctx := context.Background()

	sessConn := websocket.NetConn(ctx, c, websocket.MessageBinary)

	muxSess := muxado.Server(sessConn, &muxado.Config{
		MaxWindowSize: 1 * 1024 * 1024,
	})

	t := &MuxadoTunnel{
		muxSess:   muxSess,
		tunConfig: *tunConfig,
	}

	_, err = request(t, tunConfig)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func NewWebSocketMuxadoClientTunnel(tunReq TunnelRequest) (*MuxadoTunnel, error) {

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

	sessConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

	muxSess := muxado.Client(sessConn, &muxado.Config{})

	conn := muxSess

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

	t := &MuxadoTunnel{
		muxSess:   muxSess,
		tunConfig: tunConfig,
	}

	return t, nil
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
