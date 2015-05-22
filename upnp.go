package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"

	"github.com/huin/goupnp/httpu"
)

const (
	ssdpDiscover   = `"ssdp:discover"`
	ntsAlive       = `ssdp:alive`
	ntsByebye      = `ssdp:byebye`
	ntsUpdate      = `ssdp:update`
	ntRootDevice   = `upnp:rootdevice`
	ssdpUDP4Addr   = "239.255.255.250:1900"
	ssdpSearchPort = 1900
	methodSearch   = "M-SEARCH"
	methodNotify   = "NOTIFY"
)

func localAddresses() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Print(fmt.Errorf("localAddresses: %v\n", err.Error()))
			continue
		}
		for _, a := range addrs {
			ip, ipnet, err := net.ParseCIDR(a.String())
			if err != nil {
				log.Println(err)
				continue
			}
			if !ip.IsGlobalUnicast() {
				continue
			}
			log.Printf("%v %v %v\n", i.Name, ip, ipnet)
		}
	}
}

func init() {
	localAddresses()
}

func getMx(r *http.Request) (int, int) {
	mx, _ := strconv.Atoi(r.Header.Get("mx"))
	imx := mx
	if imx < 1 {
		imx = 1
	}
	return mx, 1 + rand.Intn(imx)
}

func msearchFunc(r *http.Request) {
	mx, _ := getMx(r)
	if mx < 1 {
		return
	}
	//log.Printf("M-SEARCH %s from %v %v", r.URL.Path, r.RemoteAddr, r)
}

func notify(addr string) {

}

func isRouteDevice(r *http.Request) bool {
	nt := r.Header.Get("Nt")
	if len(nt) < 1 {
		return false
	}

	allNt := []string{
		"urn:schemas-upnp-org:device:WANConnectionDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"urn:schemas-upnp-org:device:WANDevice:1",
		"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:Layer3Forwarding:1",
	}

	for _, pattern := range allNt {
		if pattern == nt {
			return true
		}
	}
	return false
}

func notifyFunc(r *http.Request) {
	if !isRouteDevice(r) {
		return
	}
	log.Printf("NOTIFY %s from %v: %v %v",
		r.URL.Path, r.RemoteAddr, r.Header.Get("Server"), r.Header.Get("Location"))

	resp, err := http.Get(r.Header.Get("Location"))
	if err != nil {
		return
	}
	log.Println(resp)
}

func upnpServe() {
	srv := httpu.Server{
		Addr:      ssdpUDP4Addr,
		Multicast: true,
		Handler: httpu.HandlerFunc(func(r *http.Request) {
			switch r.Method {
			case methodSearch:
				msearchFunc(r)
			case methodNotify:
				notifyFunc(r)
			default:
				log.Printf("Got %s %s from %v: %v", r.Method, r.URL.Path, r.RemoteAddr, r)
			}
		}),
	}

	err := srv.ListenAndServe()
	if err != nil {
		log.Printf("Serving failed with error: %v", err)
	}
}

func UpnpServe() {
	upnpServe()
}
