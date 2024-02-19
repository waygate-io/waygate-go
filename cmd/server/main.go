package main

import (
	"flag"

	"github.com/waygate-io/waygate-go"
)

func main() {
	adminDomainArg := flag.String("admin-domain", "", "Admin domain")
	portArg := flag.Int("port", 443, "Port")
	flag.Parse()

	config := &waygate.ServerConfig{
		AdminDomain: *adminDomainArg,
		Port:        *portArg,
	}

	server := waygate.NewServer(config)
	server.Run()
}
