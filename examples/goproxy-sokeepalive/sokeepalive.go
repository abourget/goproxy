package main

import (
	"flag"
	"log"
	"net"

	"github.com/elazarl/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Transport.Dial = func(network, addr string) (c net.Conn, err error) {
		c, err = net.Dial(network, addr)
		if c, ok := c.(*net.TCPConn); err != nil && ok {
			c.SetKeepAlive(true)
		}
		return
	}
	proxy.Verbose = *verbose
	log.Fatal(proxy.ListenAndServe(*addr))
}
