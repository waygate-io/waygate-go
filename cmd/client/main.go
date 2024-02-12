package main

import (
	"flag"

	"github.com/waygate-io/waygate-go"
)

func main() {
	serverDomainArg := flag.String("server-domain", "waygate.io", "Server domain")
	tokenArg := flag.String("token", "", "Token")
	flag.Parse()

	config := &waygate.ClientConfig{
		ServerDomain: *serverDomainArg,
		Token:        *tokenArg,
	}

	waygate.NewClient(config)
}
