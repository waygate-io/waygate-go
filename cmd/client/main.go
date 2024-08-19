package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/waygate-io/waygate-go"
)

func main() {
	serverDomainArg := flag.String("server-domain", waygate.WaygateServerDomain, "Server domain")
	tokenArg := flag.String("token", "", "Token")
	userArg := flag.String("user", "", "User")
	var forwards arrayFlags
	flag.Var(&forwards, "forward", "Forwards")

	flag.Parse()

	if *userArg == "" {
		exitOnError(errors.New("Must provide user"))
	}

	config := &waygate.ClientConfig{
		ServerDomain: *serverDomainArg,
		Token:        *tokenArg,
		Users:        []string{*userArg},
	}

	client := waygate.NewClient(config)

	for _, forward := range forwards {

		fmt.Println(forward)
		parts := strings.Split(forward, "->")

		domain := parts[0]
		target := parts[1]

		client.SetForward(&waygate.Forward{
			Domain:        domain,
			TargetAddress: target,
			Protected:     true,
		})

	}

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

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
