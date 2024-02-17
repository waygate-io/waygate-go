package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/waygate-io/waygate-go"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1>Hi there</h1>"))
	})

	tokenFlow, err := waygate.NewTokenFlow()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Println(tokenFlow.GetAuthUri())

	token, err := tokenFlow.GetToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	listener, err := waygate.Listen(token, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Println("https://" + listener.GetDomain())

	err = http.Serve(listener, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}
