package main

import (
	"flag"
	"log"
	"net/http"
	"fmt"
	"io/ioutil"
	"github.com/abourget/goproxy"
)

func makeCertificate(certPath, keyPath string) (*goproxy.GoproxyConfig, error) {
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA certificate: %s", err)
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load CA key: %s", err)
	}

	ca, err := goproxy.LoadCAConfig(cert, key)
	return ca, err
}

func main() {
	verbose := flag.Bool("v", false, "should every proxy request be logged to stdout")
	addr := flag.String("addr", ":8080", "proxy listen address")
	flag.Parse()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	log.Printf("  Generating CA Certificate...")
	// Generate a CA certificate
	ca, err := makeCertificate("/root/code/go/bin/rootCA.pem", "/root/code/go/bin/rootCA.key")
	if err != nil {
		log.Fatal("Couldn't make CA certificate.")
	}

	proxy.SetMITMCertConfig(ca)

	// test with: curl -v --proxy http://127.0.0.1:8080 -k https://google.com/

	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Logf("  1. SNIHost: %s", ctx.SNIHost())

		if ctx.SNIHost() == "google.com" {
			ctx.SetDestinationHost("www.bing.com:443")
			// so that Bing receives the right `Host:` header
			ctx.Req.Host = "www.bing.com"
		}

		return goproxy.MITM
	})

	// This checks to see if we are MITM for a regular HTTP request. If not, it passes the request forward.
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		// When doing MITM, if we've rewritten the destination host, let,s sync the
		// `Host:` header so the remote endpoints answers properly.
		ctx.Logf("  2. IsThroughMITM: %s", ctx.IsThroughMITM)

		if ctx.IsThroughMITM {
			ctx.Req.Host = ctx.Host()
			return goproxy.FORWARD // don't follow through other Request Handlers
		}
		return goproxy.NEXT
	})

	// test with: curl -v --proxy http://127.0.0.1:8080 -k https://example.com/

	// This checks the domain name. If it is example.com, it reroutes it to cheezburger.com
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Logf("  3. Host: %s", ctx.Host())

		if ctx.Host() == "example.com:80" {
			ctx.Req.Host = "www.cheezburger.com"
			ctx.Req.URL.Host = "www.cheezburger.com"
			//ctx.SetDestinationHost("www.cheezburger.com:80")
			return goproxy.FORWARD
		}
		return goproxy.NEXT
	})

	proxy.NonProxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte("hello world!\n"))
	})

	log.Println("Listening", *addr)
	log.Fatal(proxy.ListenAndServe(*addr))
}
