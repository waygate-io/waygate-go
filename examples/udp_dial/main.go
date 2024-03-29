package main

import (
	"fmt"
	"net"
	"os"

	"github.com/waygate-io/waygate-go"
)

func main() {

	udpAddr, err := net.ResolveUDPAddr("udp", "waygate.io:5757")
	checkErr(err)

	fmt.Println(udpAddr)

	conn, err := waygate.DialUDP("udp", udpAddr)
	checkErr(err)

	fmt.Println(conn)

	_, err = conn.WriteToUDP([]byte("Hi there"), udpAddr)
	checkErr(err)

	buf := make([]byte, 512)
	_, _, err = conn.ReadFromUDP(buf)
	checkErr(err)

	fmt.Println(string(buf))
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}
