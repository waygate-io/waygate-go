package main

import (
	"flag"
	"fmt"

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

	client := waygate.NewClient(config)
	eventCh := make(chan interface{})
	client.ListenEvents(eventCh)
	go client.Run()

	for {
		event := <-eventCh
		switch evt := event.(type) {
		case waygate.OAuth2AuthUriEvent:
			fmt.Println(evt.Uri)
		}
	}
}
