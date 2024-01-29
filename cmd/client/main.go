package main

import (
	"flag"

	"github.com/anderspitman/waygate-muxado-go"
)

func main() {
	serverDomainArg := flag.String("server-domain", "", "Server domain")
	adminDomainArg := flag.String("admin-domain", "", "Admin domain")
	flag.Parse()

	adminDomain := *adminDomainArg
	if adminDomain == "" {
		panic("Must provide admin domain")
	}

	config := &waygate.ClientConfig{
		ServerDomain: *serverDomainArg,
		AdminDomain:  adminDomain,
	}

	waygate.NewClient(config)
}
