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
	checkErr(err)

	fmt.Println(tokenFlow.GetAuthUri())

	token, err := tokenFlow.GetToken()
	checkErr(err)

	listener, err := waygate.Listen("tcp", "", token)
	checkErr(err)

	fmt.Println("https://" + listener.GetDomain())

	err = http.Serve(listener, nil)
	checkErr(err)
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}
