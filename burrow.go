package main

import (
	"fmt"
	"log"
	"net/http"
)

type Burrow struct {
	users map[string]string
}

var defaultBurrow Burrow

func init() {
	defaultBurrow.users = make(map[string]string)
}

func burrow(w http.ResponseWriter, r *http.Request) {
	remote := r.Header.Get("X-Real-Remote")
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	if len(remote) < 1 {
		remote = conn.RemoteAddr().String()
	}
	bufrw.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
	bufrw.WriteString(fmt.Sprintf("%s\n", remote))
	log.Println(remote)
	bufrw.Flush()
}
