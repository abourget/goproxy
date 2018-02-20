package main

import (
	"flag"
	"log"

	"github.com/abourget/goproxy"
)

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()


	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	// This is a test to see if we can allow HTTPS connections to pass through a Connect Handler
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Logf("*** In Connect Handler. Host: %s SNIHost: %s", ctx.Host(), ctx.SNIHost())
		if ctx.SNIHost() == "google.com:443" {
			ctx.Logf("Intercepted Google.com... redirecting to Bing?")

			ctx.SetDestinationHost("www.bing.com:443")
			// so that Bing receives the right `Host:` header
			ctx.Req.Host = "www.bing.com"
			return goproxy.MITM
		}

		return goproxy.FORWARD
	})


	log.Fatal(proxy.ListenAndServe(*addr))

}
