package main

import (
	"flag"

	"github.com/waygate-io/waygate-go"
)

func main() {
	serverDomainArg := flag.String("server-domain", "", "Server domain")
	flag.Parse()

	config := &waygate.ClientConfig{
		ServerDomain: *serverDomainArg,
		Token:        "yolo",
	}

	waygate.NewClient(config)
}
