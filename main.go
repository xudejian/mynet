package main

import (
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	//go UpnpServe()
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}
	addr := net.JoinHostPort(os.Getenv("HOST"), port)

	proxy := NewProxy(addr)

	log.Println("Start serve in", addr)
	err := http.ListenAndServe(addr, proxy)
	if err != nil {
		log.Fatal(err)
	}
}
