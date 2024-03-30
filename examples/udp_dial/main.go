package main

import (
	"fmt"
	"net"
	"os"

	"github.com/waygate-io/waygate-go"
)

func main() {

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:6868")
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
