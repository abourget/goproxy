[![GoDoc](https://godoc.org/github.com/nathanejohnson/intransport?status.svg)](https://godoc.org/github.com/nathanejohnson/intransport)
[![Go Report Card](https://goreportcard.com/badge/github.com/nathanejohnson/intransport)](https://goreportcard.com/report/github.com/nathanejohnson/intransport)
[![Build Status](https://api.travis-ci.org/nathanejohnson/intransport.svg?branch=master)](https://travis-ci.org/nathanejohnson/intransport)

Package intransport implements the http RoundTripper interface. This can be used with, for example, http.Client and httputil.ReverseProxy. This package is meant to allow secure communications with remote hosts that may not fully specify their intermediate certificates on the TLS handshake. Most browsers support communication with these hosts by using the issuing certificate URL from the Authority Information Access extension of the cert to fetch any missing intermediates. Each intermediate is fetched in turn until it can either complete the chain back to a trusted root or give up after all avenues have been exhausted, in which case it displays an error. Go's default transport does not fetch intermediates and will fail on mis-configured hosts. This package attempts to emulate browser behavior by attempting to complete the chain to a trusted root by fetching any missing intermediates.

Additionally, this will validate any stapled OCSP responses, and in the case where the certificate was created with the Must Staple extension set, it will fail in the absence of a validated OCSP response.

In order to use this, for most use cases, will be simply:

```go
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	
	it "github.com/nathanejohnson/intransport"
)

func main() {
	c := it.NewInTransportHTTPClient(nil)
	resp, err := c.Get("https://something.org")
	if err != nil {
		fmt.Println("boo, hiss! ", err)
		os.Exit(1)
	}
	body, err := ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {		
		fmt.Println("ba dum, tiss! ", err)
		os.Exit(1)
	}
	fmt.Printf("got response:\n%s", string(body))
}
```



