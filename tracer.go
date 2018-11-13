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
	//"net"
	//"io"
	//"os"
	"sync"
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
	StatusCode		int		// status code of the server response
	ReqBody			*[]byte		// This is a copy of the original request body (used in POSTs) if needed to replay.
	Method			*string		// The original request method.
}

type RequestTracer struct {
	Requests []traceRequest
	mu	sync.RWMutex
}

type traceRequest struct {
	matchbytes	[]byte		// Request URL matching this string will be traced. Match may occur anywhere in URL.
	expires		time.Time	// Request will be deleted after this time
	Modified	bool
	Unmodified	bool
	SkipRequest	bool
	SkipResponse	bool
	SkipInject	bool
	SkipPrivate	bool
	SkipMonitor	bool
	SkipToolbar	bool
}

/* Requests a trace. By default, will be disabled after two minutes if not triggered.
	[Host] -> Required
Optional parameters:
	modified - display modified trace for next request only
	unmodified - display the original trace for next request only
	SkipRequest - skip request handling
	SkipResponse - skip response handling
	SkipInject - skip toolbar and monitor
	SkipPrivate - Bypass the private network
	SkipMonitor - Bypass the javascript monitor injection
	SkipToolbar - Bypass the toolbar injection code
*/
func (tr *RequestTracer) RequestTrace(cmd []string, seconds int) {
	if seconds == 0 {
		seconds = 120
	}

	//fmt.Printf("[DEBUG] cmd=%v\n", cmd)
	if tr == nil || len(cmd) < 1 {
		return
	}

	host := strings.Trim(cmd[0], " ")
	host = strings.ToLower(host)

	req := traceRequest{
		matchbytes:	[]byte(host),
		expires:	time.Now().Add(time.Second * time.Duration(seconds)),
	}

	// Parse the command flags
	for _, param := range cmd {
		//fmt.Printf("[DEBUG] param=[%s]\n", param)
		switch strings.ToLower(strings.Trim(param, " ")) {
		case "modified":
			req.Modified = true
		case "unmodified":
			// Have to trace the original request because we copy values from it.
			req.Modified = true
			req.Unmodified = true
		case "skiprequest":
			req.SkipRequest = true
		case "skipresponse":
			req.SkipResponse = true
		case "skipinject":
			req.SkipInject = true
		case "skipprivate":
			req.SkipPrivate = true
		case "skipmonitor":
			req.SkipMonitor = true
		case "skiptoolbar":
			req.SkipToolbar = true
		}
	}

	// If no arguments provided, assume modified.
	if len(cmd) == 1 {
		req.Modified = true
	}

	// Only allow one active trace request. Why would we ever need more running at the same time?
	tr.mu.Lock()
	tr.Requests = []traceRequest{req}
	tr.mu.Unlock()

	//tr.Requests = append(tr.Requests,req)
}

// Returns a trace request if one has been registered for the given ctx
func (tr *RequestTracer) Trace(ctx *ProxyCtx) (traceRequest) {
	// Check for active trace request
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if len(tr.Requests) > 0 {
		for _, req := range tr.Requests {
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
						//fmt.Printf("[DEBUG] Trace matched: %s  URL=%s\n", req.matchbytes, b)
						// If it was modified or unmodified, delete the request
						if req.Modified || req.Unmodified {
							tr.Requests = []traceRequest{}
						}
						return req
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
	return traceRequest{}
}

func setupTrace(ctx *ProxyCtx, tracename string) {

	//ctx.Trace = true
	var buf []byte

	ctx.TraceInfo = &TraceInfo{
		RequestTime: time.Now().Local(),
		Name: tracename,
		originalheaders: make(map[string]string),
		ReqBody: &buf,
	}
}


func writeTrace(ctx *ProxyCtx) {
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Printf("[INFO] Trace Results [%s]:\n", ctx.TraceInfo.Name)
	fmt.Println("===========================")
	fmt.Println()

	ctx.TraceInfo.RequestDuration = time.Since(ctx.TraceInfo.RequestTime)
	ctx.TraceInfo.PrivateNetwork = ctx.PrivateNetwork
	ctx.TraceInfo.MITM = ctx.IsThroughMITM

	// Store the request handlers
	if ctx.Trace.Modified || ctx.Trace.Unmodified {
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
	for _, h := range ctx.TraceInfo.RequestHeaders {
		fmt.Printf("%+v\n", h)
	}
	fmt.Println()
	fmt.Println("Cookies sent to server:")
	for _, h := range ctx.TraceInfo.CookiesSent {
		fmt.Printf("%+v\n", h)
	}

	if ctx.TraceInfo.ReqBody != nil && len(*ctx.TraceInfo.ReqBody) > 0 {
		fmt.Println()
		fmt.Printf("Request Body: \n%s\n", string(*ctx.TraceInfo.ReqBody))
	}

	fmt.Println()
	fmt.Println("Response:")
	fmt.Println("Status:", ctx.TraceInfo.StatusCode)
	fmt.Println()
	for _, h := range ctx.TraceInfo.ResponseHeaders {
		fmt.Printf("%+v\n", h)
	}
	if len(ctx.TraceInfo.CookiesReceived) > 0 {
		fmt.Println()
		fmt.Println("Cookies received from server:")
		for _, h := range ctx.TraceInfo.CookiesReceived {
			fmt.Printf("%+v\n", h)
		}
	}

	if ctx.TraceInfo.RoundTripError != "" {
		fmt.Println()
		fmt.Printf("Server reported error: %s\n", ctx.TraceInfo.RoundTripError)
	}

	fmt.Println()

	fmt.Println()
	fmt.Printf("[INFO] End Trace [%s]:\n", ctx.TraceInfo.Name)
	fmt.Println("===========================")
	fmt.Println()

}

//
//// Used to wrap net.Conn
//type SpyConnection struct {
//	net.Conn
//	ReqBuffer bytes.Buffer
//}
//
//// Read writes all data read from the underlying connection to stderr
//func (sc *SpyConnection) Read(b []byte) (int, error) {
//
//	// TODO: Pass in the TeeReader
//	tr := io.TeeReader(sc.Conn, &sc.ReqBuffer)
//	br, err := tr.Read(b)
//	return br, err
//}
//
//// Write writes all data written to the underlying connection to stderr
//func (sc *SpyConnection) Write(b []byte) (int, error) {
//	//mw := io.MultiWriter(sc.Conn, os.Stderr)
//	//bw, err := mw.Write(b)
//	//return bw, err
//	return sc.Conn.Write(b)
//}