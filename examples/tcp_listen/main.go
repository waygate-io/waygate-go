package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/waygate-io/waygate-go"
)

func main() {

	listener, err := waygate.Listen("tcp", ":5757")
	checkErr(err)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hi there\n"))
	})

	err = http.Serve(listener, nil)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}
