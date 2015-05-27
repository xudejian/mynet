// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client implementation. See RFC 2616.
//
// This is the low-level Transport implementation of RoundTripper.
// The high-level interface is in client.go.

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultTransport is the default implementation of Transport and is
// used by DefaultClient. It establishes network connections as needed
// and caches them for reuse by subsequent calls. It uses HTTP proxies
// as directed by the $HTTP_PROXY and $NO_PROXY (or $http_proxy and
// $no_proxy) environment variables.
var DefaultTunnelTransport *Transport = &Transport{
	Proxy: http.ProxyFromEnvironment,
	Dial: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 10 * time.Second,
}

// Transport is an implementation of RoundTripper that supports HTTP,
// HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT).
// Transport can also cache connections for future re-use.
type Transport struct {
	idleMu     sync.Mutex
	wantIdle   bool // user has requested to close all idle conns
	idleConn   map[connectMethodKey][]*persistConn
	idleConnCh map[connectMethodKey]chan *persistConn

	reqMu       sync.Mutex
	reqCanceler map[*http.Request]func()

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// Dial specifies the dial function for creating unencrypted
	// TCP connections.
	// If Dial is nil, net.Dial is used.
	Dial func(network, addr string) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// If DialTLS is nil, Dial and TLSClientConfig are used.
	//
	// If DialTLS is set, the Dial hook is not used for HTTPS
	// requests and the TLSClientConfig and TLSHandshakeTimeout
	// are ignored. The returned net.Conn is assumed to already be
	// past the TLS handshake.
	DialTLS func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives, if true, prevents re-use of TCP connections
	// between different HTTP requests.
	DisableKeepAlives bool

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) to keep per-host.  If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// TODO: tunable on global max cached connections
	// TODO: tunable on timeout on cached connections
}

func closeBody(r *http.Request) {
	if r != nil && r.Body != nil {
		r.Body.Close()
	}
}

// RoundTrip implements the RoundTripper interface.
//
// For higher-level HTTP client support (such as handling of cookies
// and redirects), see Get, Post, and the Client type.
func (t *Transport) RoundTrip(req *http.Request, rw net.Conn) (err error) {
	closeBody(req)
	if req.URL == nil {
		return errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		return errors.New("http: nil Request.Header")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		//return &badStringError{"unsupported protocol scheme", req.URL.Scheme}
	}
	if req.URL.Host == "" {
		return errors.New("http: no Host in request URL")
	}
	cm, err := t.connectMethodForRequest(req)
	if err != nil {
		return err
	}

	// Get the cached or newly-created connection to either the
	// host (for http or https), the http proxy, or the http proxy
	// pre-CONNECTed to https server.  In any case, we'll be ready
	// to send it requests.
	pconn, err := t.getConn(req, cm)
	if err != nil {
		t.setReqCanceler(req, nil)
		return err
	}

	pconn.lconn = rw
	return pconn.roundTrip(req)
}

type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

// CloseIdleConnections closes any connections which were previously
// connected from previous requests but are now sitting idle in
// a "keep-alive" state. It does not interrupt any connections currently
// in use.
func (t *Transport) CloseIdleConnections() {
	t.idleMu.Lock()
	m := t.idleConn
	t.idleConn = nil
	t.idleConnCh = nil
	t.wantIdle = true
	t.idleMu.Unlock()
	for _, conns := range m {
		for _, pconn := range conns {
			pconn.close()
		}
	}
}

// CancelRequest cancels an in-flight request by closing its
// connection.
func (t *Transport) CancelRequest(req *http.Request) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	t.reqMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

//
// Private implementation past this point.
//

var (
	httpProxyEnv = &envOnce{
		names: []string{"HTTP_PROXY", "http_proxy"},
	}
	httpsProxyEnv = &envOnce{
		names: []string{"HTTPS_PROXY", "https_proxy"},
	}
	noProxyEnv = &envOnce{
		names: []string{"NO_PROXY", "no_proxy"},
	}
)

// envOnce looks up an environment variable (optionally by multiple
// names) once. It mitigates expensive lookups on some platforms
// (e.g. Windows).
type envOnce struct {
	names []string
	once  sync.Once
	val   string
}

func (e *envOnce) Get() string {
	e.once.Do(e.init)
	return e.val
}

func (e *envOnce) init() {
	for _, n := range e.names {
		e.val = os.Getenv(n)
		if e.val != "" {
			return
		}
	}
}

// reset is used by tests
func (e *envOnce) reset() {
	e.once = sync.Once{}
	e.val = ""
}

func (t *Transport) connectMethodForRequest(req *http.Request) (cm connectMethod, err error) {
	cm.targetScheme = req.URL.Scheme
	cm.targetAddr = canonicalAddr(req.URL)
	if t.Proxy != nil {
		cm.proxyURL, err = t.Proxy(req)
	}
	return cm, err
}

// proxyAuth returns the Proxy-Authorization header to set
// on requests, if applicable.
func (cm *connectMethod) proxyAuth() string {
	if cm.proxyURL == nil {
		return ""
	}
	if u := cm.proxyURL.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + basicAuth(username, password)
	}
	return ""
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// putIdleConn adds pconn to the list of idle persistent connections awaiting
// a new request.
// If pconn is no longer needed or not in a good state, putIdleConn
// returns false.
func (t *Transport) putIdleConn(pconn *persistConn) bool {
	if t.DisableKeepAlives || t.MaxIdleConnsPerHost < 0 {
		pconn.close()
		return false
	}
	if pconn.isBroken() {
		return false
	}
	key := pconn.cacheKey
	max := t.MaxIdleConnsPerHost
	if max == 0 {
		max = http.DefaultMaxIdleConnsPerHost
	}
	t.idleMu.Lock()

	waitingDialer := t.idleConnCh[key]
	select {
	case waitingDialer <- pconn:
		// We're done with this pconn and somebody else is
		// currently waiting for a conn of this type (they're
		// actively dialing, but this conn is ready
		// first). Chrome calls this socket late binding.  See
		// https://insouciant.org/tech/connection-management-in-chromium/
		t.idleMu.Unlock()
		return true
	default:
		if waitingDialer != nil {
			// They had populated this, but their dial won
			// first, so we can clean up this map entry.
			delete(t.idleConnCh, key)
		}
	}
	if t.wantIdle {
		t.idleMu.Unlock()
		pconn.close()
		return false
	}
	if t.idleConn == nil {
		t.idleConn = make(map[connectMethodKey][]*persistConn)
	}
	if len(t.idleConn[key]) >= max {
		t.idleMu.Unlock()
		pconn.close()
		return false
	}
	for _, exist := range t.idleConn[key] {
		if exist == pconn {
			log.Fatalf("dup idle pconn %p in freelist", pconn)
		}
	}
	t.idleConn[key] = append(t.idleConn[key], pconn)
	t.idleMu.Unlock()
	return true
}

// getIdleConnCh returns a channel to receive and return idle
// persistent connection for the given connectMethod.
// It may return nil, if persistent connections are not being used.
func (t *Transport) getIdleConnCh(cm connectMethod) chan *persistConn {
	if t.DisableKeepAlives {
		return nil
	}
	key := cm.key()
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	t.wantIdle = false
	if t.idleConnCh == nil {
		t.idleConnCh = make(map[connectMethodKey]chan *persistConn)
	}
	ch, ok := t.idleConnCh[key]
	if !ok {
		ch = make(chan *persistConn)
		t.idleConnCh[key] = ch
	}
	return ch
}

func (t *Transport) getIdleConn(cm connectMethod) (pconn *persistConn) {
	key := cm.key()
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if t.idleConn == nil {
		return nil
	}
	for {
		pconns, ok := t.idleConn[key]
		if !ok {
			return nil
		}
		if len(pconns) == 1 {
			pconn = pconns[0]
			delete(t.idleConn, key)
		} else {
			// 2 or more cached connections; pop last
			// TODO: queue?
			pconn = pconns[len(pconns)-1]
			t.idleConn[key] = pconns[:len(pconns)-1]
		}
		if !pconn.isBroken() {
			return
		}
	}
}

func (t *Transport) setReqCanceler(r *http.Request, fn func()) {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*http.Request]func())
	}
	if fn != nil {
		t.reqCanceler[r] = fn
	} else {
		delete(t.reqCanceler, r)
	}
}

func (t *Transport) dial(network, addr string) (c net.Conn, err error) {
	if t.Dial != nil {
		return t.Dial(network, addr)
	}
	return net.Dial(network, addr)
}

// Testing hooks:
var prePendingDial, postPendingDial func()

// getConn dials and creates a new persistConn to the target as
// specified in the connectMethod.  This includes doing a proxy CONNECT
// and/or setting up TLS.  If this doesn't return an error, the persistConn
// is ready to write requests to.
func (t *Transport) getConn(req *http.Request, cm connectMethod) (*persistConn, error) {
	if pc := t.getIdleConn(cm); pc != nil {
		log.Println("reuse ", cm, pc.conn.LocalAddr())
		return pc, nil
	}

	type dialRes struct {
		pc  *persistConn
		err error
	}
	dialc := make(chan dialRes)

	handlePendingDial := func() {
		if prePendingDial != nil {
			prePendingDial()
		}
		go func() {
			if v := <-dialc; v.err == nil {
				t.putIdleConn(v.pc)
			}
			if postPendingDial != nil {
				postPendingDial()
			}
		}()
	}

	cancelc := make(chan struct{})
	t.setReqCanceler(req, func() { close(cancelc) })

	go func() {
		pc, err := t.dialConn(cm)
		dialc <- dialRes{pc, err}
	}()

	idleConnCh := t.getIdleConnCh(cm)
	select {
	case v := <-dialc:
		// Our dial finished.
		return v.pc, v.err
	case pc := <-idleConnCh:
		// Another request finished first and its net.Conn
		// became available before our dial. Or somebody
		// else's dial that they didn't use.
		// But our dial is still going, so give it away
		// when it finishes:
		handlePendingDial()
		return pc, nil
	case <-cancelc:
		handlePendingDial()
		return nil, errors.New("net/http: request canceled while waiting for connection")
	}
}

func (t *Transport) dialConn(cm connectMethod) (*persistConn, error) {
	pconn := &persistConn{
		t:        t,
		cacheKey: cm.key(),
		reqch:    make(chan requestAndChan, 1),
		writech:  make(chan writeRequest, 1),
		closech:  make(chan struct{}),
	}
	tlsDial := t.DialTLS != nil && cm.targetScheme == "https" && cm.proxyURL == nil
	if tlsDial {
		var err error
		pconn.conn, err = t.DialTLS("tcp", cm.addr())
		if err != nil {
			return nil, err
		}
		if tc, ok := pconn.conn.(*tls.Conn); ok {
			cs := tc.ConnectionState()
			pconn.tlsState = &cs
		}
	} else {
		conn, err := t.dial("tcp", cm.addr())
		if err != nil {
			if cm.proxyURL != nil {
				err = fmt.Errorf("http: error connecting to proxy %s: %v", cm.proxyURL, err)
			}
			return nil, err
		}
		pconn.conn = conn
	}

	// Proxy setup.
	switch {
	case cm.proxyURL == nil:
		// Do nothing. Not using a proxy.
	case cm.targetScheme == "http":
		if pa := cm.proxyAuth(); pa != "" {
			pconn.mutateHeaderFunc = func(h http.Header) {
				h.Set("Proxy-Authorization", pa)
			}
		}
	case cm.targetScheme == "https":
		conn := pconn.conn
		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: cm.targetAddr},
			Host:   cm.targetAddr,
			Header: make(http.Header),
		}
		if pa := cm.proxyAuth(); pa != "" {
			connectReq.Header.Set("Proxy-Authorization", pa)
		}
		connectReq.Write(conn)

		// Read response.
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			f := strings.SplitN(resp.Status, " ", 2)
			conn.Close()
			return nil, errors.New(f[1])
		}
	}

	if cm.targetScheme == "https" && !tlsDial {
		// Initiate TLS and check remote host name against certificate.
		cfg := t.TLSClientConfig
		if cfg == nil || cfg.ServerName == "" {
			host := cm.tlsHost()
			if cfg == nil {
				cfg = &tls.Config{ServerName: host}
			} else {
				clone := *cfg // shallow clone
				clone.ServerName = host
				cfg = &clone
			}
		}
		plainConn := pconn.conn
		tlsConn := tls.Client(plainConn, cfg)
		errc := make(chan error, 2)
		var timer *time.Timer // for canceling TLS handshake
		if d := t.TLSHandshakeTimeout; d != 0 {
			timer = time.AfterFunc(d, func() {
				errc <- tlsHandshakeTimeoutError{}
			})
		}
		go func() {
			err := tlsConn.Handshake()
			if timer != nil {
				timer.Stop()
			}
			errc <- err
		}()
		if err := <-errc; err != nil {
			plainConn.Close()
			return nil, err
		}
		if !cfg.InsecureSkipVerify {
			if err := tlsConn.VerifyHostname(cfg.ServerName); err != nil {
				plainConn.Close()
				return nil, err
			}
		}
		cs := tlsConn.ConnectionState()
		pconn.tlsState = &cs
		pconn.conn = tlsConn
	}

	go pconn.readLoop()
	go pconn.writeLoop()
	return pconn, nil
}

// useProxy returns true if requests to addr should use a proxy,
// according to the NO_PROXY or no_proxy environment variable.
// addr is always a canonicalAddr with a host and port.
func useProxy(addr string) bool {
	if len(addr) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return false
		}
	}

	no_proxy := noProxyEnv.Get()
	if no_proxy == "*" {
		return false
	}

	addr = strings.ToLower(strings.TrimSpace(addr))
	if hasPort(addr) {
		addr = addr[:strings.LastIndex(addr, ":")]
	}

	for _, p := range strings.Split(no_proxy, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}
		if hasPort(p) {
			p = p[:strings.LastIndex(p, ":")]
		}
		if addr == p {
			return false
		}
		if p[0] == '.' && (strings.HasSuffix(addr, p) || addr == p[1:]) {
			// no_proxy ".foo.com" matches "bar.foo.com" or "foo.com"
			return false
		}
		if p[0] != '.' && strings.HasSuffix(addr, p) && addr[len(addr)-len(p)-1] == '.' {
			// no_proxy "foo.com" matches "bar.foo.com"
			return false
		}
	}
	return true
}

// connectMethod is the map key (in its String form) for keeping persistent
// TCP connections alive for subsequent HTTP requests.
//
// A connect method may be of the following types:
//
// Cache key form                Description
// -----------------             -------------------------
// |http|foo.com                 http directly to server, no proxy
// |https|foo.com                https directly to server, no proxy
// http://proxy.com|https|foo.com  http to proxy, then CONNECT to foo.com
// http://proxy.com|http           http to proxy, http to anywhere after that
//
// Note: no support to https to the proxy yet.
//
type connectMethod struct {
	proxyURL     *url.URL // nil for no proxy, else full proxy URL
	targetScheme string   // "http" or "https"
	targetAddr   string   // Not used if proxy + http targetScheme (4th example in table)
}

func (cm *connectMethod) key() connectMethodKey {
	proxyStr := ""
	targetAddr := cm.targetAddr
	if cm.proxyURL != nil {
		proxyStr = cm.proxyURL.String()
		if cm.targetScheme == "http" {
			targetAddr = ""
		}
	}
	return connectMethodKey{
		proxy:  proxyStr,
		scheme: cm.targetScheme,
		addr:   targetAddr,
	}
}

// addr returns the first hop "host:port" to which we need to TCP connect.
func (cm *connectMethod) addr() string {
	if cm.proxyURL != nil {
		return canonicalAddr(cm.proxyURL)
	}
	return cm.targetAddr
}

// tlsHost returns the host name to match against the peer's
// TLS certificate.
func (cm *connectMethod) tlsHost() string {
	h := cm.targetAddr
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}
	return h
}

// connectMethodKey is the map key version of connectMethod, with a
// stringified proxy URL (or the empty string) instead of a pointer to
// a URL.
type connectMethodKey struct {
	proxy, scheme, addr string
}

func (k connectMethodKey) String() string {
	// Only used by tests.
	return fmt.Sprintf("%s|%s|%s", k.proxy, k.scheme, k.addr)
}

// persistConn wraps a connection, usually a persistent one
// (but may be used for non-keep-alive requests as well)
type persistConn struct {
	t        *Transport
	cacheKey connectMethodKey
	conn     net.Conn
	lconn    net.Conn
	tlsState *tls.ConnectionState
	reqch    chan requestAndChan // written by roundTrip; read by readLoop
	writech  chan writeRequest   // written by roundTrip; read by writeLoop
	closech  chan struct{}       // closed when conn closed

	lk     sync.Mutex // guards following fields
	closed bool       // whether conn has been closed
	broken bool       // an error has happened on this connection; marked broken so it's not reused.
	// mutateHeaderFunc is an optional func to modify extra
	// headers on each outbound request before it's written. (the
	// original Request given to RoundTrip is not modified)
	mutateHeaderFunc func(http.Header)
}

// isBroken reports whether this connection is in a known broken state.
func (pc *persistConn) isBroken() bool {
	pc.lk.Lock()
	b := pc.broken
	pc.lk.Unlock()
	return b
}

func (pc *persistConn) cancelRequest() {
	pc.conn.Close()
}

func (pc *persistConn) readLoop() {
	alive := true

	rc := <-pc.reqch

	for alive {
		n, err := io.Copy(pc.lconn, pc.conn)
		if n == 0 && err == nil {
			alive = false
		}

		if err != nil {
			log.Println("server -> browser ", n, err)
			alive = false
		}

		if !alive {
			pc.markBroken()
			rc.ch <- responseAndError{err}
		}
	}
	pc.t.setReqCanceler(rc.req, nil)
	log.Println("read loop exit")
}

func (pc *persistConn) writeLoop() {
	for {
		select {
		case wr := <-pc.writech:
			if pc.isBroken() {
				wr.ch <- errors.New("http: can't write HTTP request on broken connection")
				continue
			}

			var err error
			for {
				n, err := io.Copy(pc.conn, pc.lconn)
				if err != nil {
					prefix := fmt.Sprintf("browser -> r[%s]", pc.conn.LocalAddr())
					log.Println(prefix, n, err)
					break
				}

				if err == nil && n == 0 {
					break
				}
			}
			wr.ch <- err // to the roundTrip function
			return
		case <-pc.closech:
			log.Println("write loop got close ch")
			return
		}
	}
}

type responseAndError struct {
	err error
}

type requestAndChan struct {
	req *http.Request
	ch  chan responseAndError
}

// A writeRequest is sent by the readLoop's goroutine to the
// writeLoop's goroutine to write a request while the read loop
// concurrently waits on both the write response and the server's
// reply.
type writeRequest struct {
	req *http.Request
	ch  chan<- error
}

type httpError struct {
	err     string
	timeout bool
}

func (e *httpError) Error() string   { return e.err }
func (e *httpError) Timeout() bool   { return e.timeout }
func (e *httpError) Temporary() bool { return true }

var errTimeout error = &httpError{err: "net/http: timeout awaiting response headers", timeout: true}
var errClosed error = &httpError{err: "net/http: transport closed before response was received"}

func (pc *persistConn) roundTrip(req *http.Request) (err error) {
	pc.t.setReqCanceler(req, pc.cancelRequest)

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh}

	resc := make(chan responseAndError, 1)
	pc.reqch <- requestAndChan{req, resc}

	var re responseAndError
	var pconnDeadCh = pc.closech
	var failTicker <-chan time.Time
	var respHeaderTimer <-chan time.Time
WaitResponse:
	for {
		select {
		case err := <-writeErrCh:
			if err != nil {
				re = responseAndError{err}
				pc.close()
				break WaitResponse
			}
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				respHeaderTimer = time.After(d)
			}
		case <-pconnDeadCh:
			// The persist connection is dead. This shouldn't
			// usually happen (only with Connection: close responses
			// with no response bodies), but if it does happen it
			// means either a) the remote server hung up on us
			// prematurely, or b) the readLoop sent us a response &
			// closed its closech at roughly the same time, and we
			// selected this case first, in which case a response
			// might still be coming soon.
			//
			// We can't avoid the select race in b) by using a unbuffered
			// resc channel instead, because then goroutines can
			// leak if we exit due to other errors.
			pconnDeadCh = nil                               // avoid spinning
			failTicker = time.After(100 * time.Millisecond) // arbitrary time to wait for resc
		case <-failTicker:
			re = responseAndError{err: errClosed}
			break WaitResponse
		case <-respHeaderTimer:
			pc.close()
			re = responseAndError{err: errTimeout}
			break WaitResponse
		case re = <-resc:
			break WaitResponse
		}
	}

	if re.err != nil {
		pc.t.setReqCanceler(req, nil)
	}
	pc.t.putIdleConn(pc)
	pc.lconn = nil
	return re.err
}

// markBroken marks a connection as broken (so it's not reused).
// It differs from close in that it doesn't close the underlying
// connection for use when it's still being read.
func (pc *persistConn) markBroken() {
	pc.lk.Lock()
	defer pc.lk.Unlock()
	pc.broken = true
}

func (pc *persistConn) close() {
	pc.lk.Lock()
	defer pc.lk.Unlock()
	pc.closeLocked()
}

func (pc *persistConn) closeLocked() {
	pc.broken = true
	if !pc.closed {
		pc.conn.Close()
		pc.closed = true
		close(pc.closech)
	}
	pc.mutateHeaderFunc = nil
}

var portMap = map[string]string{
	"http":  "80",
	"https": "443",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Host
	if !hasPort(addr) {
		return addr + ":" + portMap[url.Scheme]
	}
	return addr
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }
