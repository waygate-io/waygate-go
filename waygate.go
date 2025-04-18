package waygate

import (
	"fmt"
)

type MessageType uint8

func (t MessageType) String() string {
	return fmt.Sprintf("MessageType: %d", t)
}

const (
	MessageTypeTunnelConfig = iota
	MessageTypeSuccess
	MessageTypeListen
	MessageTypeStream
	MessageTypeDial
	MessageTypeError
)

type TunnelRequest struct {
	Token            string `json:"token"`
	TerminationType  string `json:"termination_type"`
	UseProxyProtocol bool   `json:"use_proxy_protocol"`
}

type TunnelConfig struct {
	Domain           string `json:"domain"`
	TerminationType  string `json:"termination_type"`
	UseProxyProtocol bool   `json:"use_proxy_protocol"`
}

type tunnel struct {
	Address string
	Client  string
}

type httpError struct {
	message    string
	statusCode int
}

func newHTTPError(statusCode int, message string) *httpError {
	return &httpError{
		message:    message,
		statusCode: statusCode,
	}
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP Error - Status code: %d - Message: %s", e.statusCode, e.message)
}

var (
	DefaultToken   string = ""
	DefaultCertDir string = "./"
	DebugMode      bool   = false
)
