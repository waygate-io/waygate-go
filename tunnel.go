package waygate

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/waygate-io/waygate-go/josencillo"
	"golang.ngrok.com/muxado/v2"
	"nhooyr.io/websocket"
)

type Tunnel interface {
	OpenStream() (connCloseWriter, error)
	AcceptStream() (connCloseWriter, error)
	GetConfig() TunnelConfig
}

type MuxadoTunnel struct {
	domain    string
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

func NewTlsMuxadoServerTunnel(tlsConn *tls.Conn, jose *josencillo.JOSE) (*MuxadoTunnel, error) {
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

	claims, err := jose.ParseJWT(tokenJwt)
	if err != nil {
		return nil, err
	}

	domain := claims["domain"].(string)

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
		domain:    domain,
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

func NewWebSocketMuxadoServerTunnel(
	w http.ResponseWriter,
	r *http.Request,
	jose *josencillo.JOSE,
) (*MuxadoTunnel, error) {

	tokenJwt := r.URL.Query().Get("token")
	if tokenJwt == "" {
		return nil, errors.New("Missing token")
	}

	claims, err := jose.ParseJWT(tokenJwt)
	if err != nil {
		return nil, err
	}

	//domain := fmt.Sprintf("test.%s", s.config.AdminDomain)
	domain := claims["domain"].(string)

	terminationType := r.URL.Query().Get("termination-type")

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return nil, err
	}

	useProxyProto := r.URL.Query().Get("use-proxy-protocol") == "true"

	tunConfig := TunnelConfig{
		Domain:           domain,
		TerminationType:  terminationType,
		UseProxyProtocol: useProxyProto,
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
		domain:    domain,
		muxSess:   muxSess,
		tunConfig: tunConfig,
	}

	return t, nil
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
