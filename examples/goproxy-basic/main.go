package main

import (
	"flag"
	"log"
	"fmt"
	"github.com/abourget/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()


	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	fmt.Printf("*** Starting proxy on port %s\n", *addr)

	// This is a test to see if we can allow HTTPS connections to pass through a Connect Handler
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		fmt.Printf("*** In Connect Handler. Host: %s SNIHost: %s\n", ctx.Host(), ctx.SNIHost())
		if ctx.SNIHost() == "google.com:443" {
			fmt.Printf("Intercepted Google.com... redirecting to Bing?\n")

			ctx.SetDestinationHost("www.bing.com:443")
			// so that Bing receives the right `Host:` header
			ctx.Req.Host = "www.bing.com"
			return goproxy.MITM
		}

		return goproxy.FORWARD
	})


	log.Fatal(proxy.ListenAndServe(*addr))

}
