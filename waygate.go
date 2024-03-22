package waygate

import ()

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

var (
	DefaultToken   string = ""
	DefaultCertDir string = "./"
	DebugMode      bool   = false
)
