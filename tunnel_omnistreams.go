package waygate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/anderspitman/omnistreams-go"
	"github.com/waygate-io/waygate-go/josencillo"
	"nhooyr.io/websocket"
)

type OmnistreamsTunnel struct {
	conn      *omnistreams.Connection
	tunConfig *TunnelConfig
}

func (t *OmnistreamsTunnel) OpenStream() (connCloseWriter, error) {
	stream, err := t.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	return omnistreamWrapper{
		ostream: stream,
	}, nil
}

func (t *OmnistreamsTunnel) AcceptStream() (connCloseWriter, error) {
	stream, err := t.conn.AcceptStream()
	if err != nil {
		return nil, err
	}

	return omnistreamWrapper{
		ostream: stream,
	}, nil
}

func (t *OmnistreamsTunnel) GetConfig() TunnelConfig {
	return *t.tunConfig
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

	bytes, err := json.Marshal(tunConfig)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	err = wsConn.Write(ctx, websocket.MessageBinary, bytes)
	if err != nil {
		return nil, err
	}

	conn := omnistreams.NewConnection(wsConn)

	t := &OmnistreamsTunnel{
		conn:      conn,
		tunConfig: tunConfig,
	}

	return t, nil
}

type omnistreamWrapper struct {
	ostream *omnistreams.Stream
}

func (w omnistreamWrapper) Read(buf []byte) (int, error) {
	return w.ostream.Read(buf)
}
func (w omnistreamWrapper) Write(buf []byte) (int, error) {
	return w.ostream.Write(buf)
}
func (w omnistreamWrapper) Close() error {
	return w.ostream.Close()
}
func (w omnistreamWrapper) CloseWrite() error {
	return w.ostream.CloseWrite()
}
func (w omnistreamWrapper) LocalAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("omnistreams-network-%d", w.ostream.StreamID()),
		address: fmt.Sprintf("omnistreams-address-%d", w.ostream.StreamID()),
	}
}
func (w omnistreamWrapper) RemoteAddr() net.Addr {
	return addr{
		network: fmt.Sprintf("omnistreams-network-%d", w.ostream.StreamID()),
		address: fmt.Sprintf("omnistreams-address-%d", w.ostream.StreamID()),
	}
}
func (w omnistreamWrapper) SetDeadline(t time.Time) error {
	return errors.New("SetDeadline not implemented")
}
func (w omnistreamWrapper) SetReadDeadline(t time.Time) error {
	return errors.New("SetReadDeadline not implemented")
}
func (w omnistreamWrapper) SetWriteDeadline(t time.Time) error {
	return errors.New("SetWriteDeadline not implemented")
}
