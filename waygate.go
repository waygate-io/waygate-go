package waygate

import (
	"embed"
	"fmt"
)

//go:embed templates names/names.json
var fs embed.FS

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

type TerminationType string

const TerminationTypeClient = "client"
const TerminationTypeServer = "server"

type TunnelRequest struct {
	Token            string `json:"token"`
	TerminationType  string `json:"termination_type"`
	UseProxyProtocol bool   `json:"use_proxy_protocol"`
	ClientName       string `json:"client_name"`
}

type TunnelConfig struct {
	Domain           string `json:"domain"`
	Token            string `json:"token"`
	TerminationType  string `json:"termination_type"`
	UseProxyProtocol bool   `json:"use_proxy_protocol"`
	ClientName       string `json:"client_name"`
}

type tunnel struct {
	Address    string
	Client     string
	ClientName string
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
