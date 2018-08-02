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
)

// Used to store information about a roundtrip.
type TraceInfo struct {
	RequestTime		time.Time
	RequestDuration		time.Duration	// Time needed to complete the request
	RequestHeaders		[]string
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

