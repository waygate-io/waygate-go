package main

import (
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
	dnsProviderArg := flag.String("dns-provider", "", "DNS Provider")
	dnsTokenArg := flag.String("dns-token", "", "DNS Token")
	dnsUserArg := flag.String("dns-user", "", "DNS User")
	noBrowserArg := flag.Bool("no-browser", false, "Use OAuth2 device flow to get tokens")
	var tunnels arrayFlags
	flag.Var(&tunnels, "tunnel", "Tunnels")

	flag.Parse()

	config := &waygate.ClientConfig{
		ServerDomain: *serverDomainArg,
		Token:        *tokenArg,
		NoBrowser:    *noBrowserArg,
		DNSProvider:  *dnsProviderArg,
		DNSUser:      *dnsUserArg,
		DNSToken:     *dnsTokenArg,
	}

	if *userArg != "" {
		config.Users = []string{*userArg}
	}

	client := waygate.NewClient(config)

	for _, tunnel := range tunnels {

		fmt.Println(tunnel)
		parts := strings.Split(tunnel, "->")

		domain := parts[0]
		target := parts[1]

		client.SetTunnel(&waygate.ClientTunnel{
			ServerAddress: domain,
			ClientAddress: target,
			Protected:     true,
		})

	}

	eventCh := make(chan interface{})
	client.ListenEvents(eventCh)
	go func() {
		err := client.Run()
		if err != nil {
			panic(err)
		}
	}()

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
