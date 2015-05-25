package main

import (
	"io"
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

func tlsHost(addr string) string {
	if hasPort(addr) {
		addr = addr[:strings.LastIndex(addr, ":")]
	}
	return addr
}

func (p *Proxy) NeedProxy(req *http.Request) bool {
	if req.Header.Get("Proxy-Agent") == proxyName {
		return false
	}

	reqHost := req.URL.Host
	if "" == reqHost {
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

func Dial(addr string) (c net.Conn, err error) {
	c, err = net.Dial("tcp", addr)
	if err != nil {
		return
	}
	return
}

func data_passby(dst, src net.Conn, prefix string, eof chan int) {
	for {
		n, err := io.Copy(dst, src)
		if err != nil {
			log.Println(prefix, err)
			break
		}
		if err == nil && n == 0 {
			break
		}
	}
	eof <- 1
}

func (p *Proxy) connectHandler(rw http.ResponseWriter, req *http.Request) {
	rconn, err := Dial(req.URL.Host)
	if err != nil {
		log.Println("dial fail", req.URL.Host, err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	defer rconn.Close()

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
	// Don't forget to close the connection:
	defer conn.Close()
	bufrw.WriteString("HTTP/1.1 200 Connection established\r\nConnection: close\r\n\r\n")
	bufrw.Flush()

	eof := make(chan int, 2)

	go data_passby(rconn, conn, "conn -> rconn", eof)
	go data_passby(conn, rconn, "rconn -> conn", eof)

	for i := 0; i < 2; i++ {
		<-eof
	}
	log.Println("done")
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if req.Method == "CONNECT" {
		p.connectHandler(rw, req)
		return
	}

	if p.NeedProxy(req) {
		log.Println("proxy", req.Method, req.RequestURI)
		req.Header.Set("Proxy-Agent", proxyName)
		p.ReverseProxy.ServeHTTP(rw, req)
		return
	}
	log.Println(req.Method, req.RequestURI)
	p.ServeMux.ServeHTTP(rw, req)
}
