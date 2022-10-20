package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func helloWorld(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Hello world\n")
}

func printPayload(w http.ResponseWriter, req *http.Request) {
	var bodyBytes []byte
	var err error

	if req.Body != nil {
		bodyBytes, err = ioutil.ReadAll(req.Body)
		if err != nil {
			fmt.Printf("Body reading error: %v", err)
			return
		}
		defer req.Body.Close()
	}

	fmt.Printf("Headers: %+v\n", req.Header)

	if len(bodyBytes) > 0 {
		var prettyJSON bytes.Buffer
		if err = json.Indent(&prettyJSON, bodyBytes, "", "\t"); err != nil {
			fmt.Printf("JSON parse error: %v", err)
			return
		}
		fmt.Println(string(prettyJSON.Bytes()))
	} else {
		fmt.Printf("Body: No Body Supplied\n")
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	// resp, err := http.DefaultTransport.RoundTrip(req)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusServiceUnavailable)
	// 	return
	// }

	fmt.Printf("Received request: %s \n", req.URL.Path)
	printPayload(w, req)

	if req.URL.Path == "/hello" {
		helloWorld(w, req)
	}
	// defer resp.Body.Close()
	// copyHeader(w.Header(), resp.Header)
	// w.WriteHeader(resp.StatusCode)
	// io.Copy(w, resp.Body)
}

func main() {

	server := &http.Server{
		Addr: ":8001",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHTTP(w, r)
		}),
		// Disable HTTP/2.
		// TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Println("Listening... on: ", server.Addr)
	log.Fatal(server.ListenAndServe())
}
