package waygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/lastlogin-net/decent-auth-go"
	"github.com/waygate-io/waygate-go/josencillo"
)

type Tunnel interface {
	OpenStream() (connCloseWriter, error)
	OpenStreamType(MessageType) (connCloseWriter, error)
	AcceptStream() (connCloseWriter, error)
	AcceptStreamType() (connCloseWriter, MessageType, error)
	GetConfig() TunnelConfig
	Request(req interface{}) (interface{}, error)
	HandleRequests(callback func(interface{}) interface{}) error
	SendDatagram(msg []byte, srcAddr, dstAddr net.Addr) error
	ReceiveDatagram() ([]byte, net.Addr, net.Addr, error)
	Events() chan TunnelEvent
}

type TunnelEvent interface{}

type TunnelEventClose struct{}

type DialRequest struct {
	Network string `json:"network"`
	Address string `json:"address"`
}
type DialResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Address string `json:"address"`
}

type ListenRequest struct {
	Network string `json:"network"`
	Address string `json:"address"`
}
type ListenResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func request(t Tunnel, req interface{}) (interface{}, error) {

	var msgType MessageType

	switch req.(type) {
	case *DialRequest:
		msgType = MessageTypeDial
	case *ListenRequest:
		msgType = MessageTypeListen
	case *TunnelConfig:
		msgType = MessageTypeTunnelConfig
	default:
		return nil, errors.New("Unknown request type")
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	reqStream, err := t.OpenStreamType(msgType)
	if err != nil {
		return nil, err
	}

	_, err = reqStream.Write(reqBytes)
	if err != nil {
		return nil, err
	}

	err = reqStream.CloseWrite()
	if err != nil {
		return nil, err
	}

	switch msgType {
	case MessageTypeTunnelConfig:
		_, err := io.ReadAll(reqStream)
		if err != nil {
			return nil, err
		}
	case MessageTypeDial:

		resBytes, err := io.ReadAll(reqStream)
		if err != nil {
			return nil, err
		}

		var res DialResponse
		err = json.Unmarshal(resBytes, &res)
		if err != nil {
			return nil, err
		}

		return &res, nil
	case MessageTypeListen:

		resBytes, err := io.ReadAll(reqStream)
		if err != nil {
			return nil, err
		}

		var listenRes ListenResponse
		err = json.Unmarshal(resBytes, &listenRes)
		if err != nil {
			return nil, err
		}

		return &listenRes, nil
	default:
		return nil, errors.New("Unknown message type for response")
	}

	return nil, nil
}

func handleRequests(t Tunnel, callback func(interface{}) interface{}) error {

	// TODO: make thread safe

	go func() {
		for {
			msgStream, msgType, err := t.AcceptStreamType()
			if err != nil {
				fmt.Println(err)
				break
			}

			reqBytes, err := io.ReadAll(msgStream)
			if err != nil {
				continue
			}

			var response interface{}

			switch msgType {
			case MessageTypeDial:
				var req DialRequest
				err = json.Unmarshal(reqBytes, &req)
				if err != nil {
					fmt.Println(err)
					continue
				}

				response = callback(&req)

			case MessageTypeListen:
				var listenReq ListenRequest
				err = json.Unmarshal(reqBytes, &listenReq)
				if err != nil {
					fmt.Println(err)
					continue
				}

				response = callback(&listenReq)

			default:
				fmt.Println("Unknown message type", msgType)
				continue
			}

			resBytes, err := json.Marshal(response)
			if err != nil {
				fmt.Println(err)
				continue
			}

			_, err = msgStream.Write(resBytes)
			if err != nil {
				fmt.Println(err)
				continue
			}

			err = msgStream.CloseWrite()
			if err != nil {
				fmt.Println(err)
				continue
			}
		}
	}()

	return nil
}

func processRequest(tunnelReq TunnelRequest, tunnelDomains []string, jose *josencillo.JOSE, session *decentauth.Session, public bool) (*TunnelConfig, error) {

	var host string
	if DebugMode {
		host = "debug"
	} else {
		var err error

		nameGen, err := NewNameGenerator()
		if err != nil {
			return nil, err
		}

		host = nameGen.GenerateName()
	}

	var domain string
	if session == nil {
		if !public {
			return nil, newHTTPError(401, "No token provided")
		}

		if len(tunnelDomains) == 0 {
			return nil, newHTTPError(400, "No tunnel domains")
		}

		domain = strings.ToLower(host) + "." + tunnelDomains[0]
	} else {
		dom, exists := session.CustomData["domain"]
		if !exists {
			return nil, newHTTPError(500, "No domain assigned to session")
		}

		domain = dom
	}

	tunConfig := &TunnelConfig{
		Domain:           domain,
		TerminationType:  tunnelReq.TerminationType,
		UseProxyProtocol: tunnelReq.UseProxyProtocol,
		ClientName:       tunnelReq.ClientName,
	}

	return tunConfig, nil
}

func readStreamType(stream io.Reader) (MessageType, error) {

	msgTypeBuf := make([]byte, 1)
	n, err := stream.Read(msgTypeBuf)
	if err != nil {
		return MessageTypeError, err
	}

	if n != 1 {
		return MessageTypeError, errors.New("Read wrong number of bytes")
	}

	msgType := MessageType(msgTypeBuf[0])

	return msgType, nil
}

func streamFirstWrite(stream io.Writer, buf []byte, msgType MessageType) error {

	prependedBuf := make([]byte, len(buf)+1)
	copy(prependedBuf[1:], buf)
	prependedBuf[0] = byte(msgType)
	_, err := stream.Write(prependedBuf)
	if err != nil {
		return err
	}

	return nil
}

type stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	CloseWrite() error
}


