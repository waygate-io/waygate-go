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
	"sync"

	"github.com/anderspitman/dashtui"
	"github.com/mailgun/proxyproto"
	"github.com/omnistreams/omnistreams-go"
	"github.com/omnistreams/omnistreams-go/transports"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/waygate-io/waygate-go/josencillo"
	//"github.com/gizak/termui/v3"
	//"github.com/gizak/termui/v3/widgets"
)

type OmnistreamsTunnel struct {
	conn           *omnistreams.Connection
	tunConfig      *TunnelConfig
	eventChans     []chan TunnelEvent
	datagramStream *omnistreams.Stream
	mut            *sync.Mutex
}

type authError error

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

	msg, err := t.datagramStream.ReadMessage()
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

	_, err = t.datagramStream.Write(prependedBuf.Bytes())
	if err != nil {
		return err
	}

	return nil
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

func (t *OmnistreamsTunnel) Events() chan TunnelEvent {
	eventCh := make(chan TunnelEvent, 1)

	t.mut.Lock()
	defer t.mut.Unlock()

	t.eventChans = append(t.eventChans, eventCh)
	return eventCh
}

func (t *OmnistreamsTunnel) emit(evt interface{}) {
	t.mut.Lock()
	chans := t.eventChans
	t.mut.Unlock()

	for _, ch := range chans {
		ch <- evt
	}
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
		ClientName:       r.URL.Query().Get("client-name"),
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

	t := &OmnistreamsTunnel{
		conn:       conn,
		tunConfig:  tunConfig,
		mut:        &sync.Mutex{},
		eventChans: []chan TunnelEvent{},
	}

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

		t.emit(TunnelEventClose{})
	}()

	_, err = request(t, tunConfig)
	if err != nil {
		return nil, err
	}

	datagramStream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}

	// TODO: feels hacky. We need to send some data because the receiving
	// side doesn't know a stream has been created until data arrives.
	// Consider adding an explicit "Open Stream" frame in omnistreams, or
	// use heartbeat/ping frames once those are implemented since we'll
	// need them anyway
	datagramStream.Write([]byte("open-datagram-stream"))

	t.datagramStream = datagramStream

	return t, nil
}

func NewOmnistreamsClientTunnel(tunReq TunnelRequest) (*OmnistreamsTunnel, error) {

	ctx := context.Background()

	uri := fmt.Sprintf("wss://%s/waygate?token=%s&termination-type=%s&use-proxy-protocol=%t&client-name=%s",
		WaygateServerDomain,
		tunReq.Token,
		tunReq.TerminationType,
		tunReq.UseProxyProtocol,
		tunReq.ClientName,
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

	datagramStream, err := conn.AcceptStream()
	if err != nil {
		return nil, err
	}

	if datagramStream.StreamID() != 4 {
		return nil, fmt.Errorf("Wrong streamID for datagram stream: %d", datagramStream.StreamID())
	}

	msg, err := datagramStream.ReadMessage()
	if err != nil {
		return nil, err
	}

	msgStr := string(msg)
	if msgStr != "open-datagram-stream" {
		return nil, fmt.Errorf("Incorrect first datagram message: %s", msgStr)
	}

	t := &OmnistreamsTunnel{
		conn:           conn,
		tunConfig:      &tunConfig,
		mut:            &sync.Mutex{},
		eventChans:     []chan TunnelEvent{},
		datagramStream: datagramStream,
	}

	return t, nil
}
