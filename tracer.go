/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, February 2018
*/

/* Tracer implements functionality to gather diagnostic information about how Winston is modifying requests.
 */

package goproxy

import (
	"time"
	"bytes"
	"fmt"
	"strings"
)

// Used to store information about a roundtrip.
type TraceInfo struct {
	Name			string		// Will be printed out at beginning of trace output.
	RequestTime		time.Time
	RequestDuration		time.Duration	// Time needed to complete the request
	RequestHeaders		[]string
	originalheaders		map[string]string	// Used to store original headers in order to duplicate request
	ResponseHeaders		[]string
	PrivateNetwork		bool		// If true, the request was cloaked
	MITM			bool		// if true, then we were able to intercept the request. Wil be false for clients which don't trust us.
	RoundTripError		string		// Errors recorded by roundtrip
	CookiesSent		[]string	// Cookies sent with the request
	CookiesReceived		[]string	// Cookies received from the server
}

type RequestTracer struct {
	Requests []traceRequest
}

type traceRequest struct {
	matchbytes	[]byte		// Request URL matching this string will be traced. Match may occur anywhere in URL.
	expires		time.Time	// Request will be deleted after this time
}

// Requests a trace. By default, will be deleted after two minutes if not triggered.
func (tr *RequestTracer) RequestTrace(match []byte, seconds int) {
	if seconds == 0 {
		seconds = 120
	}

	if tr == nil {
		return
	}
	
	tr.Requests = append(tr.Requests, traceRequest{
		matchbytes:	match,
		expires:	time.Now().Add(time.Second * time.Duration(seconds)),
	})
}

// Returns true if the given request should be traced and removes the item from the trace request list.
func (tr *RequestTracer) Trace(ctx *ProxyCtx) (bool) {


	// Check for active trace request
	if len(tr.Requests) > 0 {
		for ind, req := range tr.Requests {
			if req.expires.After(time.Now()) {
				b, err := ctx.Req.URL.MarshalBinary()
				// If URL is relative, preface with the host
				if !ctx.Req.URL.IsAbs() {
					host := []byte(ctx.Req.Host)
					b = append(host, b...)
					//fmt.Printf("[WARN] Relative URL sent to Trace: %s\n", string(b))
				}
				if err == nil {
					if bytes.Contains(b, req.matchbytes) {
						//fmt.Printf("*** Trace matched: %s\n, req.matchbytes")
						// delete the entry
						tr.Requests[ind] = tr.Requests[len(tr.Requests) - 1]
						tr.Requests = tr.Requests[:len(tr.Requests)-1]

						return true
					}
				}
			}
		}

		// Check for expired tracerequests and delete the first one.
		for ind, req := range tr.Requests {
			if req.expires.Before(time.Now()) {
				tr.Requests[ind] = tr.Requests[len(tr.Requests) - 1]
				tr.Requests = tr.Requests[:len(tr.Requests)-1]
				break
			}
		}
	}
	return false
}

func setupTrace(ctx *ProxyCtx, tracename string) {

	ctx.Trace = true
	ctx.TraceInfo = &TraceInfo{
		RequestTime: time.Now().Local(),
		Name: tracename,
		originalheaders: make(map[string]string),
	}
}

func writeTrace(ctx *ProxyCtx) {
	fmt.Println()
	fmt.Printf("[INFO] Trace Results [%s]:\n", ctx.TraceInfo.Name)
	fmt.Println("===========================")
	fmt.Println()

	ctx.TraceInfo.RequestDuration = time.Since(ctx.TraceInfo.RequestTime)
	ctx.TraceInfo.PrivateNetwork = ctx.PrivateNetwork
	ctx.TraceInfo.MITM = ctx.IsThroughMITM

	// Store the request handlers
	fmt.Printf("# Request Headers 1: %d\n", len(ctx.TraceInfo.RequestHeaders))
	if ctx.Trace {
		for name, headers := range ctx.Req.Header {
			name = strings.ToLower(name)
			for _, h := range headers {
				ctx.TraceInfo.RequestHeaders = append(ctx.TraceInfo.RequestHeaders, fmt.Sprintf("%v: %v", name, h))
			}
		}
	}

	cookies := ctx.Req.Header.Get("Cookie")
	for _, c := range strings.Split(cookies, ";") {
		ctx.TraceInfo.CookiesSent = append(ctx.TraceInfo.CookiesSent, c)
	}

	// Note: Response fields are written in OnResponse()


	fmt.Printf("URL: %s\n", ctx.Req.URL)
	fmt.Printf("Time: %v\n", ctx.TraceInfo.RequestTime)
	fmt.Printf("Duration: %v\n", ctx.TraceInfo.RequestDuration)
	fmt.Printf("Private: %t\n", ctx.TraceInfo.PrivateNetwork)
	fmt.Printf("Decrypted: %t\n", ctx.TraceInfo.MITM)
	fmt.Println()
	fmt.Println("Request:")
	fmt.Printf("# Request Headers 2: %d\n", len(ctx.TraceInfo.RequestHeaders))
	for _, h := range ctx.TraceInfo.RequestHeaders {
		fmt.Printf("%+v\n", h)
	}
	fmt.Println()
	fmt.Println("Cookies sent to server:")
	for _, h := range ctx.TraceInfo.CookiesSent {
		fmt.Printf("%+v\n", h)
	}

	fmt.Println()
	fmt.Println("Response:")
	for _, h := range ctx.TraceInfo.ResponseHeaders {
		fmt.Printf("%+v\n", h)
	}
	fmt.Println()
	fmt.Println("Cookies received from server:")
	for _, h := range ctx.TraceInfo.CookiesReceived {
		fmt.Printf("%+v\n", h)
	}

	if ctx.TraceInfo.RoundTripError != "" {
		fmt.Println()
		fmt.Printf("Server reported error: %s\n", ctx.TraceInfo.RoundTripError)
	}

	fmt.Println("===========================")
	fmt.Println()

}
