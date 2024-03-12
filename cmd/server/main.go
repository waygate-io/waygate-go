package main

import (
	"flag"

	"github.com/waygate-io/waygate-go"
)

func main() {
	adminDomainArg := flag.String("admin-domain", "", "Admin domain")
	portArg := flag.Int("port", 443, "Port")
	public := flag.Bool("public", false, "Create tunnels for unauthenticated clients")
	var tunnelDomains arrayFlags
	flag.Var(&tunnelDomains, "tunnel-domain", "Tunnel domains")
	flag.Parse()

	config := &waygate.ServerConfig{
		AdminDomain:   *adminDomainArg,
		Port:          *portArg,
		Public:        *public,
		TunnelDomains: tunnelDomains,
	}

	server := waygate.NewServer(config)
	server.Run()
}

// Taken from https://stackoverflow.com/a/28323276/943814
type arrayFlags []string

func (i *arrayFlags) String() string {
	return "arrayFlags string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
