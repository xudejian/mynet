package main

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

const (
	proxyName = "mynet"
)

type Proxy struct {
	listenHost string
	listenPort string
	*httputil.ReverseProxy
	*http.ServeMux
}

func director(req *http.Request) {
	if "" == req.URL.Host {
		req.URL.Host = req.Host
	}

	if "" == req.URL.Scheme {
		req.URL.Scheme = "http"
	}
}

func NewProxy(addr string) *Proxy {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalln("listenAddr fail", addr, err)
	}

	return &Proxy{
		host,
		port,
		&httputil.ReverseProxy{Director: director},
		http.NewServeMux(),
	}
}

func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

func (p *Proxy) NeedProxy(req *http.Request) bool {
	if req.Header.Get("Proxy-Agent") == proxyName {
		return false
	}

	reqHost := req.URL.Host
	if "" == reqHost {
		return false
		reqHost = req.Host
	}
	if "" == reqHost {
		return false
	}

	if !hasPort(reqHost) {
		return true
	}

	host, port, err := net.SplitHostPort(reqHost)
	if err != nil {
		return false
	}

	if port != p.listenPort {
		return true
	}

	if host == p.listenHost {
		return false
	}

	if "" == p.listenHost {
		switch host {
		case "127.0.0.1":
			return false
		case "localhost":
			return false
		case "::1":
			return false
		case "fe80::1":
			return false
		}
	}
	return true
}

func (p *Proxy) connectHandler(rw http.ResponseWriter, req *http.Request) {
	hj, ok := rw.(http.Hijacker)
	if !ok {
		http.Error(rw, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	bufrw.WriteString("HTTP/1.1 200 Connection established\r\nConnection: close\r\n\r\n")
	bufrw.Flush()

	go func(req *http.Request, conn net.Conn) {
		defer conn.Close()
		err := DefaultTunnelTransport.RoundTrip(req, conn)
		if err != nil {
			log.Println("tunnel transport fail", err)
			return
		}
	}(req, conn)
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if req.Method == "CONNECT" {
		p.connectHandler(rw, req)
		return
	}

	if p.NeedProxy(req) {
		req.Header.Set("Proxy-Agent", proxyName)
		p.ReverseProxy.ServeHTTP(rw, req)
		return
	}
	p.ServeMux.ServeHTTP(rw, req)
}
