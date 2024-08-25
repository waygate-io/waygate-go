package waygate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/anderspitman/dashtui"
	"github.com/omnistreams/omnistreams-go"
	"github.com/omnistreams/omnistreams-go/transports"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/waygate-io/waygate-go/josencillo"
	//"github.com/gizak/termui/v3"
	//"github.com/gizak/termui/v3/widgets"
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

	return &streamWrapper{
		msgType:         msgType,
		sendMessageType: true,
		stream:          stream,
		id:              stream.StreamID(),
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

	return &streamWrapper{
		msgType:         msgType,
		sendMessageType: false,
		stream:          stream,
		id:              stream.StreamID(),
	}, msgType, nil
}

func (t *OmnistreamsTunnel) SendMessage(msg interface{}) (interface{}, error) {
	return request(t, msg)
}

func (t *OmnistreamsTunnel) ReceiveDatagram() ([]byte, net.Addr, net.Addr, error) {
	//msg, err := t.conn.ReceiveMessage()
	//if err != nil {
	//	return nil, nil, nil, err
	//}

	//reader := bytes.NewReader(msg)

	//ppHeader, err := proxyproto.ReadHeader(reader)
	//if err != nil {
	//	return nil, nil, nil, err
	//}

	//remaining, err := io.ReadAll(reader)
	//if err != nil {
	//	return nil, nil, nil, err
	//}

	//return remaining, ppHeader.Source, ppHeader.Destination, nil
	time.Sleep(10 * time.Second)
	return nil, nil, nil, errors.New("OmnistreamsTunnel.ReceiveDatagram not implemented")
}

func (t *OmnistreamsTunnel) SendDatagram(msg []byte, srcAddr, dstAddr net.Addr) error {

	//conn := &wrapperConn{
	//	localAddr:  dstAddr,
	//	remoteAddr: srcAddr,
	//}

	//// TODO: maybe pass addr.IP as serverName?
	//proxyHeader, err := buildProxyProtoHeader(conn, "")
	//if err != nil {
	//	return err
	//}

	//prependedBuf := &bytes.Buffer{}

	//_, err = proxyHeader.WriteTo(prependedBuf)
	//if err != nil {
	//	return err
	//}

	//_, err = prependedBuf.Write(msg)
	//if err != nil {
	//	return err
	//}

	//return t.conn.SendMessage(prependedBuf.Bytes())

	time.Sleep(10 * time.Second)
	return errors.New("OmnistreamsTunnel.SendDatagram not implemented")
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
	numStreamsGauge prometheus.Gauge,
	dash *dashtui.DashTUI,
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

	wr, err := transports.NewWebSocketServerTransport(w, r)
	if err != nil {
		return nil, err
	}

	conn := omnistreams.NewConnection(wr, false)

	eventCh := conn.Events()
	go func() {
		numStreams := 0
		for evt := range eventCh {
			switch e := evt.(type) {
			case *omnistreams.StreamCreatedEvent:
				numStreams++
				dash.Set("num-streams", float64(numStreams))

				numStreamsGauge.Inc()
			case *omnistreams.StreamDeletedEvent:
				numStreams--
				dash.Set("num-streams", float64(numStreams))

				numStreamsGauge.Dec()
			case omnistreams.DebugEvent:
				count += int(e)
				dash.Set("debug", float64(count))
			default:
				fmt.Println("Unknown omnistreams event", evt)
			}
		}
	}()

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

	wr, err := transports.NewWebSocketClientTransport(ctx, uri)
	if err != nil {
		return nil, err
	}

	conn := omnistreams.NewConnection(wr, true)

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
