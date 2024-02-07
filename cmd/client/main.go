package main

import (
	"flag"

	"github.com/anderspitman/waygate-muxado-go"
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
