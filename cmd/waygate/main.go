package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anderspitman/reanimator-go"
	"github.com/waygate-io/waygate-go"
)

var Version string

// Taken from https://stackoverflow.com/a/28323276/943814
type arrayFlags []string

func (i *arrayFlags) String() string {
	return "arrayFlags string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	reanimator.Supervise()

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Must specify a command\n")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		fmt.Fprintf(os.Stderr, "Invalid command: '%s'\n", command)
		os.Exit(1)
	}
}

func runServer() {
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	adminDomainArg := flagSet.String("domain", "", "Server domain")
	portArg := flagSet.Int("port", 443, "Port")
	public := flagSet.Bool("public", false, "Create tunnels for unauthenticated clients")
	dnsProvider := flagSet.String("dns-provider", "", "DNS Provider")
	dnsToken := flagSet.String("dns-token", "", "DNS Token")
	dnsUser := flagSet.String("dns-user", "", "DNS User")
	debug := flagSet.Bool("debug", false, "Enable debug mode")
	//disableTui := flagSet.Bool("disable-tui", false, "Disable TUI")
	disableTui := flagSet.Bool("disable-tui", true, "Disable TUI")
	tuiDisplayPeriod := flagSet.Duration("tui-display-period", 100*time.Millisecond, "TUI Display Refresh Period")
	var tunnelDomains arrayFlags
	flagSet.Var(&tunnelDomains, "tunnel-domain", "Tunnel domains")
	var users arrayFlags
	flagSet.Var(&users, "user", "Users array")
	flagSet.Parse(os.Args[2:])

	waygate.DebugMode = *debug

	config := &waygate.ServerConfig{
		AdminDomain:      *adminDomainArg,
		Port:             *portArg,
		Public:           *public,
		DnsProvider:      *dnsProvider,
		DnsToken:         *dnsToken,
		DnsUser:          *dnsUser,
		TunnelDomains:    tunnelDomains,
		DisableTUI:       *disableTui,
		TUIDisplayPeriod: *tuiDisplayPeriod,
		Users:            users,
	}

	server := waygate.NewServer(config)

	fmt.Printf("Running Waygate Server Version: %s\n", Version)
	os.Exit(server.Run())
}

func runClient() {
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	serverURIArg := flagSet.String("server-uri", waygate.WaygateServerDomain, "Server API URI")
	tokenArg := flagSet.String("token", "", "Token")
	userArg := flagSet.String("user", "", "User")
	dnsProviderArg := flagSet.String("dns-provider", "", "DNS Provider")
	dnsTokenArg := flagSet.String("dns-token", "", "DNS Token")
	dnsUserArg := flagSet.String("dns-user", "", "DNS User")
	noBrowserArg := flagSet.Bool("no-browser", false, "Use OAuth2 device flow to get tokens")
	var tunnels arrayFlags
	flagSet.Var(&tunnels, "tunnel", "Tunnels")

	fmt.Println(os.Args, "user:", *userArg)

	flagSet.Parse(os.Args[2:])

	config := &waygate.ClientConfig{
		ServerURI:   *serverURIArg,
		Token:       *tokenArg,
		NoBrowser:   *noBrowserArg,
		DNSProvider: *dnsProviderArg,
		DNSUser:     *dnsUserArg,
		DNSToken:    *dnsTokenArg,
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
