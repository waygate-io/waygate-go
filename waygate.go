package waygate

import (
	"golang.ngrok.com/muxado/v2"
)

type Tunnel struct {
	muxSess muxado.Session
	config  TunnelConfig
}

type TunnelConfig struct {
	Domain           string `json:"domain"`
	TerminationType  string `json:"termination_type"`
	UseProxyProtocol bool   `json:"use_proxy_protocol"`
}
