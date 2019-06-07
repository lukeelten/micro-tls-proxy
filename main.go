package main

import (
	"log"
	"net/http"
)

func main() {
	config := LoadConfig()
	err := config.Validate()
	if err != nil {
		log.Fatal(err)
	}

	proxyServer, err := NewProxy(config)
	if err != nil {
		log.Fatal(err)
	}

	err = proxyServer.Run()
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
