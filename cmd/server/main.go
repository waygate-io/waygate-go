package main

import (
	"flag"

	"github.com/anderspitman/waygate-muxado-go"
)

func main() {
	adminDomainArg := flag.String("admin-domain", "", "Admin domain")
	flag.Parse()

	config := &waygate.ServerConfig{
		AdminDomain: *adminDomainArg,
	}

	server := waygate.NewServer(config)
	server.Run()
}
