package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/anderspitman/symbiote-go"
	"github.com/waygate-io/waygate-go"
)

var Version string

func main() {
	symbiote.Supervise()

	adminDomainArg := flag.String("admin-domain", "", "Admin domain")
	portArg := flag.Int("port", 443, "Port")
	public := flag.Bool("public", false, "Create tunnels for unauthenticated clients")
	dnsProvider := flag.String("dns-provider", "", "DNS Provider")
	dnsToken := flag.String("dns-token", "", "DNS Token")
	dnsUser := flag.String("dns-user", "", "DNS User")
	debug := flag.Bool("debug", false, "Enable debug mode")
	//disableTui := flag.Bool("disable-tui", false, "Disable TUI")
	disableTui := flag.Bool("disable-tui", true, "Disable TUI")
	tuiDisplayPeriod := flag.Duration("tui-display-period", 100*time.Millisecond, "TUI Display Refresh Period")
	var tunnelDomains arrayFlags
	flag.Var(&tunnelDomains, "tunnel-domain", "Tunnel domains")
	var users arrayFlags
	flag.Var(&users, "user", "Users array")
	flag.Parse()

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

// Taken from https://stackoverflow.com/a/28323276/943814
type arrayFlags []string

func (i *arrayFlags) String() string {
	return "arrayFlags string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
