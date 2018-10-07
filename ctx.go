// Numerous changes made to ctx class from the original abourget package
// including the addition of a fast, persistent whitelist for domains which
// failed TLS handshake protocols (typically resulting from mobile apps)
// Be sure to diff!

package goproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"github.com/inconshreveable/go-vhost"
	"path/filepath"
	"time"
	"net/textproto"
	"sync"
	"context"
	"github.com/benburkert/dns"
	"github.com/winston/shadownetwork"
	"net/url"
	"crypto/rand"
	//"runtime/debug"
)

var NonHTTPRequest = "nonhttprequest"

// ProxyCtx is the Proxy context, contains useful information about every request. It is passed to
// every user function. Also used as a logger.
type ProxyCtx struct {
	Method            string
	SourceIP          string
	IsSecure          bool            // Whether we are handling an HTTPS request with the client
	IsThroughMITM     bool            // Whether the current request is currently being MITM'd
	IsThroughTunnel   bool            // Whether the current request is going through a CONNECT tunnel, doing HTTP calls (non-secure)
	IsNonHttpProtocol bool            // Set to true if a MITM request is determined to not be a HTTP 1.0-1.2 protocol.
	NonHTTPRequest	  []byte	  // The original request if a non non-HTTP protocol is detected

	host              string          // Sniffed and non-sniffed hosts, cached here.
	sniHost           string

	sniffedTLS        bool
	MITMCertConfig    *GoproxyConfig

	connectScheme     string

	  // OriginalRequest holds a copy of the request before doing some HTTP tunnelling
	  // through CONNECT, or doing a man-in-the-middle attack.
	OriginalRequest   *http.Request

	  // Contains the request and response streams from the proxy to the
	  // downstream server in the case of a MITM connection
	Req            *http.Request
	ResponseWriter http.ResponseWriter

  	// Connections, up (the requester) and downstream (the server we forward to)
	Conn           net.Conn
	targetSiteConn net.Conn           // used internally when we established a CONNECT session,
					  // to pass through new requests

					  // Resp contains the remote sever's response (if available). This can be nil if the
					  // request wasn't sent yet, or if there was an error trying to fetch the response.
					  // In this case, refer to `ResponseError` for the latest error.
					  // RLS: In the case of MITM, this is the client's response stream
	Resp *http.Response

					  // ResponseError contains the last error, if any, after running `ForwardRequest()`
					  // explicitly, or implicitly forwarding a request through other means (like returning
					  // `FORWARD` in some handlers).
	ResponseError error

					  // originalResponseBody holds the first Response.Body (the original Response) in the chain.  This possibly exists if `Resp` is not nil.
	originalResponseBody io.ReadCloser

					  // RoundTripper is used to send a request to a remote server when
					  // forwarding a Request.  If you set your own RoundTripper, then
					  // `FakeDestinationDNS` and `LogToHARFile` will have no effect.
	RoundTripper            RoundTripper
	fakeDestinationDNS      string

					  // HAR logging
	isLogEnabled            bool
	isLogWithContent        bool

					  // will contain the recent error that occured while trying to send receive or parse traffic
	Error                   error

					  // UserObjects and UserData allow you to keep data between
					  // Connect, Request and Response handlers.
	UserObjects             map[string]interface{}
	UserData                map[string]string

					  // Will connect a request to a response
	Session                 int64
	Proxy                   *ProxyHttpServer

					  // Closure to alert listeners that a TLS handshake failed
					  // RLS 6-29-2017
	Tlsfailure              func(ctx *ProxyCtx, untrustedCertificate bool)

					  // References to persistent caches for statistics collection
					  // RLS 7-5-2017
	IgnoreCounter		bool // if true, this request won't be counted (used for streaming)

	// Client signature
	// https://blog.squarelemon.com/tls-fingerprinting/
	CipherSignature         string

	NewBodyLength           int
	VerbosityLevel          uint16

					  	// 11/2/2017 - Used for replacement macros (user agents)
	DeviceType int
	Whitelisted     	bool      	// If true, response filtering will be completely disabled and local DNS will be bypassed.
	TimeRemaining		int		// Time remaining in sec for temporary whitelisting or uncloaking

					  	// Keeps a list of any messages we want to pass back to the client
	StatusMessage   	[]string

					  	// Request handler sets this to true if it thinks it is a first party request
	FirstParty      	bool

					  	// Set to true to use private network
	PrivateNetwork  	bool

					  	// If a shadow transport is being used, this points to it.
	ShadowTransport *shadownetwork.ShadowTransport

					  	// If true, then Winston diagnostic information will be recorded about the current request
	Trace           bool

	TraceInfo       *TraceInfo        	// Information about the original request/response
	SkipRequestHandler bool	  		// If set to true, then response handler will be skipped
	SkipResponseHandler bool	  	// If set to true, then response handler will be skipped
	RequestTime		time.Time	// Time the request was started. Useful for debugging.
	Referrer		string		// Referrer taken from HTTP request. Used for logging.
	CookiesModified		int		// # of cookies blocked or modified for the current request. Used for logging.
	ElementsModified	int		// # of page elements removed or modified for the current request. Used for logging.

}

// Append a message to the context. This will be sent back to the client as a "Winston-Response" header.
func (ctx *ProxyCtx) RecordStatus(msg string) {
	if len(ctx.StatusMessage) == 0 {
		ctx.StatusMessage = make([]string, 1)
		ctx.StatusMessage[0] = msg
	} else {
		ctx.StatusMessage = append(ctx.StatusMessage, msg)
	}
}

// SNIHost will try preempt the TLS handshake and try to sniff the
// Server Name Indication.  It returns `Host()` for non CONNECT
// requests, so it is always safe to call.  If it sniffed
// successfully, but didn't find anything, it is possible to return an
// empty string.
func (ctx *ProxyCtx) SNIHost() string {
	if ctx.Method != "CONNECT" {
		return ctx.Host()
	}

	if ctx.sniffedTLS {
		//ctx.Logf("SNIHost: Already sniffed SNI %s: ", ctx.sniHost)
		return ctx.sniHost
	}

	// TODO: Are we replying with the wrong HTTP version here?
	fmt.Println("[TODO] Check HTTP 1/0 response to sender here (1).")
	ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

	// Wrap the original connection in a muxer
	tlsConn, err := vhost.TLS(ctx.Conn)
	ctx.Conn = net.Conn(tlsConn)
	ctx.sniffedTLS = true
	if err != nil {
		//ctx.Logf("Failed to sniff SNI (falling back to request Host): %s", err)
		return ctx.Host()
	}

	// TODO: make sure we put a ":port" on the `host` if there was one previously...

	// Sniff the host
	sniHost := tlsConn.Host()

	if sniHost != "" {
		// Fix: if host hasn't been set yet, then the original code defaults to port
		// 80 instead of port 443. We fix by checking for a blank host, then
		// setting the port to 443 because we're expecting a TLS connection by default.
		if ctx.Host() == "" {
			ctx.host = sniHost + ":443"
		} else {
			// Our host wasn't blank, so change it to sniHost + the original port
			ctx.SetDestinationHost(inheritPort(sniHost, ctx.Host()))
		}
		ctx.sniHost = ctx.Host()
	}
	return ctx.sniHost
}

// Host() returns the "host:port" to which your request will be
// forwarded. For a CONNECT request, it is preloaded with the original
// request's "host:port". For other methods, it is preloaded with the
// request's host and an added port based on the scheme (unless the
// port was specified).
//
// If you sniff the SNI host with `ctx.SNIHost()`, it will alter the
// value returned by `Host()` to reflect what was sniffed.  You need
// that to properly MITM secure CONNECT calls, otherwise the remote
// end will always fail to recognize the certificates this lib signs
// on-the-fly.
//
// You can alter this value with `SetDestinationHost()`.
func (ctx *ProxyCtx) Host() string {
	return ctx.host
}

// SetDestinationHost sets the "host:port" to which you want to
// FORWARD or MITM a CONNECT request.  Otherwise defaults to what was
// in the `CONNECT` request. If you call `SNIHost()` to sniff SNI,
// then this will override the destination host automatically.
//
// If you want to alter the destination host of a *Request* that goes
// through a tunnel you can eavesdrop, modify `ctx.Req.URL.Host`, the
// RoundTrip will go to that address, even though the `ctx.Req.Host`
// is used as the `Host:` header. You can identify those requests with
// `ctx.IsThroughMITM` or `ctx.IsThroughTunnel`.
func (ctx *ProxyCtx) SetDestinationHost(host string) {
	//ctx.Logf("SetDestinationHost(%s)", host)
	ctx.host = inheritPort(host, ctx.host)
}

// FakeDestinationDNS will force a connection to the specified host/ip
// instead of the normal DNS resolution of the `SetDestinationHost()`.
// This will assume the destination server will answer as if it was
// ctx.Host().
//
// If you specify a port, it will also serve in the redirection,
// otherwise the port from `ctx.Host()` will be used.
func (ctx *ProxyCtx) FakeDestinationDNS(host string) {
	ctx.fakeDestinationDNS = inheritPort(host, ctx.Host())
}

// RLS - in order to support unit testing, we have to support port #s other than port 80 and 443. To do this,
// we'll fall back on the actual request URL scheme.
func (ctx *ProxyCtx) getConnectScheme() string {
	//fmt.Println("[TEST] getConnectScheme()", ctx.connectScheme, ctx.host, ctx.Req.URL.Scheme)
	if ctx.connectScheme == "" {
		if strings.HasSuffix(ctx.host, ":80") {
			return "http"
		} else if strings.HasSuffix(ctx.host, ":443") {
			return "https"
		} else if ctx.Req.URL.Scheme == "https" {
			return "https"
		} else {
			return "http"
		}
	}
	return ctx.connectScheme
}

// SetConnectScheme determines how to interprete the TCP conversation
// following a CONNECT request. `scheme` can be "http" or "https". By
// default, it uses a simple heuristic: "http" if CONNECT asked for
// port 80, otherwise it always assumes "https" when trying to
// man-in-the-middle. Call this before returning `MITM` from Connect
// Handlers.
func (ctx *ProxyCtx) SetConnectScheme(scheme string) {
	if scheme != "http" && scheme != "https" {
		panic(`invalid scheme passed to "SetConnectScheme", use "http" or "https" only.`)
	}

	ctx.connectScheme = scheme
}

// CONNECT handling methods

// ManInTheMiddle triggers either a full-fledged MITM when done through HTTPS, otherwise, simply tunnels future
// HTTP requests through the CONNECT stream, dispatching calls to the Request Handlers
func (ctx *ProxyCtx) ManInTheMiddle() error {
	if ctx.getConnectScheme() == "http" {
		fmt.Println("[DEBUG] ManInTheMiddle() - bypassing TunnelHTTP(). This should only happen for websockets requests.")
		ctx.Proxy.DispatchRequestHandlers(ctx)
	} else {
		return ctx.ManInTheMiddleHTTPS()
	}
	return nil

}

// TunnelHTTP assumes the current connection is a plain HTTP tunnel,
// with no security. It then dispatches all future requests in there
// through the registered Request Handlers.
//
// Requests flowing through this tunnel will be marked `ctx.IsThroughTunnel == true`.
//
// You can also find the original CONNECT request in `ctx.OriginalRequest`.
func (ctx *ProxyCtx) TunnelHTTP() error {
	//if ctx.Method != "CONNECT" {
	//	panic("method is not CONNECT")
	//}
	fmt.Printf("[DEBUG] TunnelHTTP() %s\n", ctx.host)

	if ctx.IsSecure && !ctx.sniffedTLS {
		fmt.Println("[TODO] Check HTTP 1/0 response to sender here (2).")
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}

	//ctx.Logf("Assuming CONNECT is plain HTTP tunneling, mitm proxying it")

	targetSiteConn, err := ctx.Proxy.connectDial("tcp", ctx.host)
	if err != nil {
		fmt.Printf("[DEBUG] TunnelHTTP() error %+v\n", err)
		ctx.Warnf("Error dialing to %s: %s", ctx.host, err.Error())
		return err
	}

	ctx.OriginalRequest = ctx.Req
	ctx.targetSiteConn = targetSiteConn

	// Note: RoundTripper() will be ignored if a non-http protocol is detected
	ctx.RoundTripper = RoundTripperFunc(func(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {

		// Those requests will go through the CONNECT'ed tunnel, not Dial out directly on our own.
		remote := bufio.NewReader(ctx.targetSiteConn)
		resp := ctx.Resp
		if err := req.Write(ctx.targetSiteConn); err != nil {
			ctx.httpError(err)
			return nil, err
		}
		resp, err = http.ReadResponse(remote, req)
		if err != nil {
			ctx.httpError(err)
			return nil, err
		}
		return resp, nil
	})

	//for {
		// RLS - We already have the request. Not sure why they are trying to read it again. This hangs.
		//client := bufio.NewReader(ctx.Conn)
		//req, err := http.ReadRequest(client)
		//fmt.Printf("[DEBUG] TunnelHTTP() 4.2 %s\n", ctx.host)
		//if err != nil && err != io.EOF {
		//	ctx.Warnf("cannot read request of MITM HTTP client: %+#v", err)
		//}
		//fmt.Printf("[DEBUG] TunnelHTTP() 4.3 %s\n", ctx.host)
		//if err != nil {
		//	fmt.Printf("[DEBUG] TunnelHTTP() 4.4 %s\n", ctx.host)
		//	return err
		//}
		//fmt.Printf("[DEBUG] TunnelHTTP() 4.5 %s\n", ctx.host)
		//ctx.Req = req
		ctx.IsThroughTunnel = true

		fmt.Printf("[DEBUG] TunnelHTTP() dispatching request handlers...\n")
		ctx.Proxy.DispatchRequestHandlers(ctx)
	//}

	return nil
}

var ipregex = regexp.MustCompile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])`)
func validIP4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")

	//re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])`)
	if ipregex.MatchString(ipAddress) {
		return true
	}
	return false
}


// ManIntheMiddleHTTPS assumes we're dealing with an TLS-wrapped
// CONNECT tunnel.  It will perform a full-blown man-in-the-middle
// attack, and forward any future requests received from inside the
// TSL tunnel to the Request Handlers.
//
// Requests in there will be marked `IsSecure = true` (although, you
// and me know it's not *totally* secure, huh ?). They will also have
// the `ctx.IsThroughMITM` flag set to true.
//
// The `ctx.OriginalRequest`
// will also hold the original CONNECT request from which the tunnel
// originated.
func (ctx *ProxyCtx) ManInTheMiddleHTTPS() error {
	// Attempt to recover gracefully from a nested panic not caught by the later defer recover.
	// This is a very rare race condition which happens only under high load but which
	// unfortunately crashes the device.
	defer func() {
		if r := recover(); r != nil {
			ctx.Logf(1, "[PANIC] Fatal error while processing MITM request. Recovering gracefully.", r)
		}
	}()
	if ctx.Method != "CONNECT" {
		fmt.Println("[ERROR] Attempting to MITM a non-CONNECT request")
		panic("method is not CONNECT")
	}

	// Use to debug non-SNI requests
	isIpAddress := validIP4(ctx.host)

	// If we haven't already sniffed, send a 200 OK back to the client
	if ctx.IsSecure && !ctx.sniffedTLS {
		fmt.Println("[TODO] Check HTTP 1/0 response to sender here (3).")
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}
	signHost := ctx.sniHost
	if signHost == "" {
		signHost = ctx.host
		if !ctx.sniffedTLS {
			ctx.Warnf("ManInTheMiddleHTTPS - Sign Host: No SNI host sniffed, falling back to CONNECT host." +
				"  Risks being rejected by requester. To avoid that, call SNIHost() " +
				"before doing MITM. %s", signHost)
			//panic("stopping execution")
		}
	}
	// DEBUG - uncomment to ignore all other MITM requests
	//if !strings.Contains(ctx.host, "cbssports.com") {
	//	return nil
	//}

	// This is our TLS server to handle client requests. See signer.go and certs.go.
	tlsConfig, err := ctx.tlsConfig(signHost)
	// We should always be able to get a certificate when a signhost has been provided
	if !isIpAddress && err != nil {
		ctx.Logf(1, "ManInTheMiddleHTTPS - Couldn't configure MITM TLS tunnel: %s", err)
		ctx.httpError(err)
		return err
	}

	// This contains the original connection with the client
	ctx.OriginalRequest = ctx.Req

	// this goes in a separate goroutine, so that the net/http server won't think we're
	// still handling the request even after hijacking the connection. Those HTTP CONNECT
	// request can take forever, and the server will be stuck when "closed".
	// TODO: Allow Server.Close() mechanism to shut down this connection as nicely as possible
	//fmt.Println()
	//fmt.Printf("[DEBUG] ctx.go - MITM: %s\n", ctx.Host())
	go func(ctx *ProxyCtx) {
		// Found a rare but irreproducible race condition when calling isEof() with many
		// active connections at the same time. This ensures that only the active connection
		// goes down and doesn't take the entire process with it.
		// RLS 3-11-2018 - Also recovers from occasional panics on line ~576:
		//     subReq, err := http.ReadRequest(clientTlsReader)
		defer func() {
			if r := recover(); r != nil {
				ctx.Logf(1, "Error (2): Panic while processing MITM request. Recovering gracefully.", r)
			}
		}()

		r := ctx.Req

		// Set a reasonable timeout to complete the handshake
		// Note: This timeout affects downloads, so we'll probably have to extend it.
		timeoutDuration := 15 * 60 * time.Second
		ctx.Conn.SetReadDeadline(time.Now().Add(timeoutDuration))
		ctx.Conn.SetWriteDeadline(time.Now().Add(timeoutDuration))

		// Set it again on the muxed connection, otherwise tls/conn.go/readFromUntil may hang
		// if the client doesn't send enough information.
		rawClientTls := tls.Server(ctx.Conn, tlsConfig)
		rawClientTls.SetReadDeadline(time.Now().Add(timeoutDuration))
		rawClientTls.SetWriteDeadline(time.Now().Add(timeoutDuration))

		// FIX 9/13/2017: the deferred close must come before the Handshake because if it
		// errors out, the connection is left open and we end up with thousands of orphaned objects.
		defer func() {
			defer ctx.Conn.Close()
			rawClientTls.Close()
		}()
		//defer rawClientTls.Close()

		// Performs the TLS handshake
		//if ctx.Trace {
		//	fmt.Printf("[DEBUG] About to handshake: %s\n", ctx.host)
		//}

		if err := rawClientTls.Handshake(); err != nil {
			// A handshake error typically only occurs on the client side
			// when pinned Certificates are being used, ie: a mobile
			// application refuses to trust our local CA.
			// Note: This can also happen if a browser window is closed while resources are loading.

			// Is anyone listening? Let them know the TLS handshake failed.
			if ctx.Tlsfailure != nil {
				//fmt.Printf("[DEBUG] ctx.TLSHandshake error (client) - %s %+v [%s]\n", ctx.Req.URL.String(), err, ctx.CipherSignature)
				ctx.Tlsfailure(ctx, true)
			}

			return
		}
		ctx.Conn = rawClientTls
		ctx.IsSecure = true

		// Use to detect timeouts
		start := time.Now()

		// Handshake worked. Try to process the request.

		readRequest := true

		// Use a teereader so we can recover the request if it failed
		var buf bytes.Buffer
		tee := io.TeeReader(rawClientTls, &buf)
		clientTlsReader := bufio.NewReader(tee)

		var subReq *http.Request
		subReq, err = http.ReadRequest(clientTlsReader)
		if err != nil && err == io.EOF {
			// The client dropped the connection. This indicates a problem communicating through the client TLS tunnel
			// most likely due certificate pinning or the client does not have the Winston certificate installed.
			// Note that when browser tabs are closed, they may rapidly shut down all TLS connections in progress.
			// We attempt to filter these out by only registering a TLS certificate error if the connection closed
			// pretty quickly. This works because Firefox typically takes a few seconds to drop the connection,
			// while untrusting clients will drop the connection immediately.
			if ctx.RequestTime.Add(time.Second * 1).After(time.Now()) {
				//fmt.Printf("[DEBUG] Client hung up on TLS connection after handshake (1). Calling NoCertificate(). [%s] [%s] elapsed time: %s\n", ctx.host, ctx.CipherSignature, time.Since(ctx.RequestTime))
				if ctx.Tlsfailure != nil {
					ctx.Tlsfailure(ctx, true)
				}
			}
			return
		}

		//if strings.Contains(ctx.host, "aha.io") {
		//if ctx.Trace {
			//fmt.Printf("[DEBUG] Read request results: %s err=%+v\n", ctx.host, err)

			// Uncomment to print out raw request.
			//fmt.Printf("[DEBUG] Read so far (%d bytes):\n%s\n", buf.Len(), buf.String())

			// Uncomment to read rest of request.body. Will prevent request from completing.
			//body, ok := ioutil.ReadAll(clientTlsReader)
			//fmt.Printf("[DEBUG] Remaining Request.Body [%t]:\n%s\n", ok, string(body))
		//}

		// If we read anything, then we know there wasn't a certificate failure.
		n := buf.Len()

		// We failed to parse a standard http request. Try to parse it as non-http.
		if err != nil && n > 0 {
			//if ctx.Trace {
				fmt.Printf("[DEBUG] Creating new non-httprequest: %s \n", ctx.host)
			//}
			// Manually create a new request

			subReq = &http.Request{
				Method:     "",
				URL:	&url.URL{
					Host: ctx.host,
				},
				Proto:      "nonhttps",
				ProtoMajor: 0,
				ProtoMinor: 0,
				Header:     make(http.Header),
				Body:       nil,
				Host:       ctx.host,
				RequestURI: ctx.host,
			}


			//fmt.Printf("[DEBUG] Non HTTP protocol received. Original request: [%s] len=%d err=%v\n%s\n", ctx.Req.URL.String(), n, err, buf)
			//clientTlsReader := bufio.NewReader(&buf)
			//subReq, err = ctx.readRequest(clientTlsReader, true)

			ctx.IsNonHttpProtocol = true
			originalrequest := buf.Bytes()
			ctx.NonHTTPRequest = originalrequest
			err = nil


		}



		if err != nil {
			if ctx.Trace {
				fmt.Printf("[DEBUG] Request creation failed: %s err=%+v\n", ctx.host, err)
			}
			//	fmt.Printf("[DEBUG] Client hung up on TLS connection after handshake (2). Calling NoCertificate(). [%s] [%s] elapsed time: %s\n", ctx.host, ctx.CipherSignature, time.Since(ctx.RequestTime))
			if ctx.Tlsfailure != nil {
				//fmt.Println("[DEBUG] malformed HTTP request - calling whitelisting logic")
				ctx.Tlsfailure(ctx, true)
			}
			return
		}

		// Copy the request
		if ctx.Trace {
			// Copy the original method.
			if ctx.TraceInfo.Method == nil {
				origmethod := subReq.Method
				ctx.TraceInfo.Method = &origmethod
			} else {
				subReq.Method = *ctx.TraceInfo.Method
			}
			// If we don't have a request body, then copy it
			if ctx.TraceInfo.ReqBody == nil || len(*ctx.TraceInfo.ReqBody) == 0 {
				buf, _ := ioutil.ReadAll(subReq.Body)
				//buf = append(buf, byte('\n'))
				ctx.TraceInfo.ReqBody = &buf
				//rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
				rdr2 := ioutil.NopCloser(bytes.NewBuffer(*ctx.TraceInfo.ReqBody))

				// Close original body so we don't leak the connection
				subReq.Body.Close()
				subReq.Body = rdr2

				//fmt.Printf("[DEBUG] Copying original http.Request [%p] (%d)\n%s\n", ctx.TraceInfo.ReqBody, len(*ctx.TraceInfo.ReqBody), string(*ctx.TraceInfo.ReqBody))
			} else {
				// Otherwise, we have an existing request body so send it as part of this request.
				rdr2 := ioutil.NopCloser(bytes.NewBuffer(*ctx.TraceInfo.ReqBody))
				subReq.Body.Close()
				subReq.Body = rdr2
				// Setting ContentLength doesn't work for some reason.
				//subReq.ContentLength = int64(len(*ctx.TraceInfo.ReqBody))
				subReq.Header.Set("content-length", strconv.Itoa(len(*ctx.TraceInfo.ReqBody)))
			}
		}

		subReq.URL.Scheme = "https"

		// Unit testing: We only intercept requests which were destined for port 443, but we can invoke a proxy
		// and point it at other ports when unit testing. To accommodate this scenario, check for the presence of
		// a host header and if it exists, update ctx.host. WINSTON-2-8
		//fmt.Println("[DEBUG] ", subReq.Host)
		_, port, err := net.SplitHostPort(subReq.Host)
		if err == nil && port != "443" {
			//fmt.Printf("[WARN] ManInTheMiddleHTTPS() - modified ctx.host from %s to %s. This should only happen in unit testing or TLS Winston client API calls\n", ctx.host, subReq.Host)
			ctx.host = subReq.Host
		}

		subReq.URL.Host = ctx.host
		subReq.RemoteAddr = r.RemoteAddr // since we're converting the request, need to carry over the original connecting IP as well

		ctx.Req = subReq
		ctx.IsThroughMITM = true

		// Give custom listener a chance to service the request
		//if strings.Contains(ctx.host, "winston.conf") {
		//	fmt.Println("[DEBUG] ManInTheMiddleHTTPS() 6", ctx.host)
		//}

		if ctx.Proxy.HandleHTTP != nil {
			// TODO: If we ever want to serve anything other than our JSON API, we should add header support.
			// The HandleHTTP() function is responsible for completing the request and piping the
			// response body back to the original client. For this to work, we need to update
			// ctx.ResponseWriter so that it points to the newly established TLS connection.
			// Note that the goproxy dumbreponsewriter cannot write headers, so we wrote a slightly
			// less dumb one.

			// TIP: For debugging http responses, use curl:
			//  curl -gkv https://winston.conf:82/api/total_bandwidth

			// TODO: Wrap it in a real responsewriter
			ctx.ResponseWriter = notsodumbResponseWriter{
				ctx.Conn,
				&http.Header{}}

			ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n"))
			ctx.Proxy.HandleHTTP(ctx)

			ctx.Conn.Write([]byte("\r\n"))
			ctx.Conn.Close()
			return
		}

		ctx.Proxy.DispatchRequestHandlers(ctx)

		// Auto-whitelist failed TLS connections and IP addresses. These tend to be streaming requests.
		// Some clients (Google Mobile in particular) will handshake but then drop the connection after they process
		// the certificate. We have to whitelist these or Google Play, Google Photos and other Google clients will
		// not work.
		// TODO: Diagnose the root of Google Android certificate errors. Possibly mismatched ciphers with BoringSSL?
		if !readRequest || isIpAddress {
			// Note: Some websites (google in particular) send HTTPS requests as keep alives
			// and don't close them. They end up timing out. We don't want to whitelist these.
			// In contrast, smart clients and devices close the connection immediately when they
			// don't trust the certificate. We'll use this here to prevent whitelisting
			// keep alive requests while detecting smart devices that should be tunnelled.
			end := time.Now()
			duration := end.Sub(start) / time.Millisecond

			if duration < 30 || isIpAddress {
				//ctx.Logf(1, "[WARN] Client dropped connection or IP address detected. Whitelisting this device... [%s]", ctx.Req.URL)

				// whitelist certain sites across an entire network.
				if ctx.Tlsfailure != nil {
					// TODO: We have to be more conservative. Good requests should prevent whitelisting for some period of time.
					// Browser connection issues are common and will frequently cause whitelisting to occur.

					if n == 0 {
						// We couldn't read any bytes of the request, so consider it a certificate failure
						fmt.Printf("[ERROR] TLS Failure (client dropped connection) [%s]\n", ctx.host)
						ctx.Tlsfailure(ctx, true)
					} else {
						// Was IP Address
						fmt.Printf("[ERROR] TLS Failure (bad request) [%s]\n", ctx.host)
						ctx.Tlsfailure(ctx, false)
					}
				}
			}
		}


		// MITM calls are asynchronous so we have to record the trace information here
		if ctx.Trace {
			writeTrace(ctx)
		}
	}(ctx)

	return nil
}

// Grafts the provided io.Closer to the provided Request body.
// Request.Body will be consumed and closed by the native Golang Client
// methods Do, Post, and PostForm, and Transport.RoundTrip.
//
// If body is of type *bytes.Buffer, *bytes.Reader, or
// *strings.Reader, the returned request's ContentLength is set to its
// exact value (instead of -1), GetBody is populated (so 307 and 308
// redirects can replay the body), and Body is set to NoBody if the
// ContentLength is 0.
func (ctx *ProxyCtx) SetRequestBody(req *http.Request, body io.Reader) (error) {
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	// The host's colon:port should be normalized. See Issue 14836.
	req.Body = rc
	if body != nil {
		switch v := body.(type) {
		case *bytes.Buffer:
			req.ContentLength = int64(v.Len())
			buf := v.Bytes()
			req.GetBody = func() (io.ReadCloser, error) {
				r := bytes.NewReader(buf)
				return ioutil.NopCloser(r), nil
			}
		case *bytes.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		case *strings.Reader:
			req.ContentLength = int64(v.Len())
			snapshot := *v
			req.GetBody = func() (io.ReadCloser, error) {
				r := snapshot
				return ioutil.NopCloser(&r), nil
			}
		default:
		// This is where we'd set it to -1 (at least
		// if body != NoBody) to mean unknown, but
		// that broke people during the Go 1.8 testing
		// period. People depend on it being 0 I
		// guess. Maybe retry later. See Issue 18117.
		}
		// For client requests, Request.ContentLength of 0
		// means either actually 0, or unknown. The only way
		// to explicitly say that the ContentLength is zero is
		// to set the Body to nil. But turns out too much code
		// depends on NewRequest returning a non-nil Body,
		// so we use a well-known ReadCloser variable instead
		// and have the http package also treat that sentinel
		// variable to mean explicitly zero.
		if req.GetBody != nil && req.ContentLength == 0 {
			req.Body = http.NoBody
			req.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		}
	}

	return  nil
}


// Taken from http/request.go. Modified to support non-standard protocols coming over port 443.
/*
func (ctx *ProxyCtx) readRequest(b *bufio.Reader, deleteHostHeader bool) (req *http.Request, err error) {
	tp := newTextprotoReader(b)
	req = new(http.Request)

	// First line: GET /index.html HTTP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}

	defer func() {
		putTextprotoReader(tp)

		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	var ok bool
	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)


	if !ok {
		ctx.IsNonHttpProtocol = true
	}

	if !validMethod(req.Method) {
		ctx.IsNonHttpProtocol = true
		//return nil, fmt.Errorf("invalid method %s\nRequest line:\n%s\n", req.Method, s)
	}

	rawurl := req.RequestURI

	if req.ProtoMajor, req.ProtoMinor, ok = ParseHTTPVersion(req.Proto); !ok {
		ctx.IsNonHttpProtocol = true
		//return nil, fmt.Errorf("malformed HTTP version", req.Proto)
	}

	// CONNECT requests are used two different ways, and neither uses a full URL:
	// The standard use is to tunnel HTTPS through an HTTP proxy.
	// It looks like "CONNECT www.google.com:443 HTTP/1.1", and the parameter is
	// just the authority section of a URL. This information should go in req.URL.Host.
	//

	// The net/rpc package also uses CONNECT, but there the parameter is a path
	// that starts with a slash. It can be parsed with the regular URL parser,
	// and the path will end up in req.URL.Path, where it needs to be in order for
	// RPC to work.
	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")

	if justAuthority {
		rawurl = "http://" + rawurl
	}

	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		req.RequestURI = ctx.host
		ctx.IsNonHttpProtocol = true
	}

	// Skip the rest of processing.
	if ctx.IsNonHttpProtocol {
		req.URL = &url.URL{
			Host: ctx.host,
		}
		req.Header = http.Header{}
		return req, nil
	}


	if justAuthority {
		// Strip the bogus "http://" back off.
		req.URL.Scheme = ""
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = http.Header(mimeHeader)

	// RFC 2616: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same. In the second case, any Host line is ignored.
	req.Host = req.URL.Host

	if req.Host == "" {
		req.Host = req.Header.Get("Host")
	}
	if deleteHostHeader {
		delete(req.Header, "Host")
	}
	fixPragmaCacheControl(req.Header)

	req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header, false)

	// Not sure what this does. Try living without it.
	//err = readTransfer(req, b)

	if err != nil {
		return nil, err
	}

	if isH2Upgrade(req) {
		// Because it's neither chunked, nor declared:
		req.ContentLength = -1

		// We want to give handlers a chance to hijack the
		// connection, but we need to prevent the Server from
		// dealing with the connection further if it's not
		// hijacked. Set Close to ensure that:
		req.Close = true
	}
	return req, nil
}
*/


/*func validMethod(method string) bool {
	return len(method) > 0
}

// RFC 2616: Should treat
//	Pragma: no-cache
// like
//	Cache-Control: no-cache
func fixPragmaCacheControl(header http.Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}

func isH2Upgrade (r *http.Request) bool {
	return r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0"
}*/

// Determine whether to hang up after sending a request and body, or
// receiving a response and body
// 'header' is the request headers
/*func shouldClose(major, minor int, header http.Header, removeCloseHeader bool) bool {
	if major < 1 {
		return true
	}

	conv := header["Connection"]

	hasClose := httplex.HeaderValuesContainsToken(conv, "close")

	if major == 1 && minor == 0 {
		return hasClose || !httplex.HeaderValuesContainsToken(conv, "keep-alive")
	}

	if hasClose && removeCloseHeader {
		header.Del("Connection")
	}

	return hasClose
}*/

// formatRequest generates ascii representation of a request. Used to pretty print http.Request.
/*
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string
	// Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
	r.ParseForm()
	request = append(request, "\n")
	request = append(request, r.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}
*/

// Given a short header from an incoming request, determines if it is a valid HTTP request that Golang will accept
/*func isHTTP(firstline string) (bool) {

		fmt.Printf("*** firstline: %s\n", firstline)
		// Retrieve the three parts of the request
		_, _, proto, ok := parseRequestLine(string(firstline))
		if !ok {
			return false
		}

		_, _, ok = ParseHTTPVersion(proto)
		return ok
}*/
// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
// Taken from request.go
/*func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}*/

// ParseHTTPVersion parses a HTTP version string.

// "HTTP/1.0" returns (1, 0, true).

/*func ParseHTTPVersion(vers string) (major, minor int, ok bool) {
	const Big = 1000000 // arbitrary upper bound
	switch vers {
	case "HTTP/1.1":
		return 1, 1, true
	case "HTTP/1.0":
		return 1, 0, true
	}
	if !strings.HasPrefix(vers, "HTTP/") {
		return 0, 0, false
	}
	dot := strings.Index(vers, ".")
	if dot < 0 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(vers[5:dot])
	if err != nil || major < 0 || major > Big {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(vers[dot+1:])
	if err != nil || minor < 0 || minor > Big {
		return 0, 0, false
	}
	return major, minor, true
}*/

/* Debugging code for TLS handshaking code */

var textprotoReaderPool sync.Pool

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}
func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func (ctx *ProxyCtx) HijackConnect() net.Conn {
	if ctx.Method != "CONNECT" {
		panic("method is not CONNECT when HijackConnect() is called")
	}

	if !ctx.sniffedTLS {
		fmt.Println("[TODO] Check HTTP 1/0 response to sender here (4).")
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}

	return ctx.Conn
}

// This is used to pipe a request directly through to the target site back to the client via MITM.
// In the original goproxy implementation, this was used only for CONNECT requests. However, we also
// use it to pipe non-HTTP protocols through.
func (ctx *ProxyCtx) ForwardConnect() error {
	var dnsbypassctx context.Context

	if ctx.Whitelisted {
		//ctx.Logf(1, "  *** ForwardConnect() - Bypassing DNS for whitelisted host [%s]", ctx.host)
		dnsbypassctx = context.WithValue(ctx.Req.Context(), dns.UpstreamKey, 0)
	}

	targetSiteConn, err := ctx.Proxy.connectDialContext(dnsbypassctx, "tcp", ctx.host)
	if err != nil {
		fmt.Printf("[DEBUG] ForwardConnect: error - %+v\n", err)
		ctx.httpError(err)
		return err
	}

	if !ctx.sniffedTLS && ctx.IsSecure {
		fmt.Println("[TODO] Check HTTP 1/0 response to sender here (5).")
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}

	fuse(ctx.Conn, targetSiteConn, ctx.Host())


	// RLS 9/13/2017 - These are closed together because they run in different goroutines.
	// This ensures that closing one doesn't cause the other https connection to abort.
	// See: https://github.com/elazarl/goproxy/pull/161
	// Still slowly leaking memory with Abourget's code.
	//toClose := make(chan net.Conn)
	//go ctx.copyAndClose(targetSiteConn, ctx.Conn, toClose)
	//go ctx.copyAndClose(ctx.Conn, targetSiteConn, toClose)
	//ctx.closeTogether(toClose)


	return nil
}

//var hasPort = regexp.MustCompile(`:\d+$`)

func (ctx *ProxyCtx) RejectConnect() {
	if ctx.Method != "CONNECT" {
		panic("cannot RejectConnect() when Method is not CONNECT")
	}

	// we had support here for flushing the Response when ctx.Resp was != nil.
	// this belongs to an upper layer, not down here.  Have your code do it instead.
	if !ctx.sniffedTLS {
		fmt.Println("[TODO] Check HTTP 1/0 response to sender here (6).")
		ctx.Conn.Write([]byte("HTTP/1.0 502 Rejected\r\n\r\n"))
	}

	ctx.Conn.Close()
}

// Note: if you get certificate errors for certain sites, you can debug them on the device using:
// openssl s_client -connect xxxxx.com:443 |tee logfile
//
// Also consider debugging TLS with Curl: https://curl.haxx.se/docs/sslcerts.html
// This command displays helpful info, such as the location of the local certificate store. If you want the actual
// certificate being served by the site, you will need to ensure it's not being blocked by DNS.
//	curl -kv https://xxxxx.com:443
//
// To configure local CA certificates
//
// Standard Linux certs (some are bad, like Wosign)
//	dpkg-reconfigure ca-certificates
// this will regenerate the file in /etc/ca-certificates.conf (see http://manpages.ubuntu.com/manpages/bionic/man8/update-ca-certificates.8.html)
//
// A better source can be found at https://android.googlesource.com/platform/system/ca-certificates/+/master/files/
// Untar to /usr/share/ca-certificates and copy all of the filenames to the /etc/ca-certificates.conf file
//
// Then run
//	update-ca-certificates
// This will use the above file to regenerate /etc/ssl/certs


// Used for protocols that are "http-like" (ie: websockets).
// Opens a connection, serializes the original request to it and sets up a tunnel, allowing further
// communication to take place (if none, it will close).
// TODO: Should we add websockets protocol support so we can inspect packets?
// TODO: Add P2P support
// TODO: Add Timeouts
func (ctx *ProxyCtx) ForwardNonHTTPRequest(host string) error {
	var targetSiteConn net.Conn
	var err error

	 //If the request was whitelisted, then use the upstream DNS.
	dnsbypassctx := ctx.Req.Context()
	if ctx.Whitelisted {
		dnsbypassctx = context.WithValue(ctx.Req.Context(), dns.UpstreamKey, 0)
	}

	// Send in a pointer to a struct that RoundTrip can modify to let us know if there was an error calling out to the private network
	dnsbypassctx = context.WithValue(dnsbypassctx, shadownetwork.ShadowTransportFailed, &shadownetwork.ShadowNetworkFailure{})

	if !ctx.IsSecure {
		d := HijackedDNSDialer()
		targetSiteConn, err = d.DialContext(dnsbypassctx, "tcp", ctx.host)
		if err != nil {
			fmt.Printf("[DEBUG] ForwardNonHTTPRequest: Couldn't dial tcp connection - error - %+v\n", err)
			ctx.httpError(err)
			return err
		}
	} else {
		// Set up a TLS connection to the downstream site

		// unit testing: Ignore verification with self-signed certificates coming from localhost
		skipverification := false
		if strings.HasPrefix(ctx.host, "127.0.0.") {
			skipverification = true
		}
		targetSiteConn, err = tls.DialWithDialer(HijackedDNSDialer(), "tcp", ctx.host, &tls.Config{InsecureSkipVerify: skipverification})
		if err != nil {
			fmt.Printf("[DEBUG] ForwardNonHTTPRequest: Couldn't dial TLS connection - error - %+v\n", err)
			ctx.httpError(err)
			return err
		}
	}

	// Enforce an idle timeout (60 seconds)
	//clientConnIdle := &IdleTimeoutConn{Conn: ctx.Conn}
	//targetSiteConnIdle := &IdleTimeoutConn{Conn: targetSiteConn}

	// Write request to server
	err = ctx.Req.Write(targetSiteConn)
	if err != nil {
		fmt.Printf("[DEBUG] ForwardNonHTTPRequest(): couldn't write request - error - %+v\n", err)
		return err
	}

	// Tunnel the connections together and block until they close.
	fuse(ctx.Conn, targetSiteConn, ctx.Host())
	//fmt.Printf("[DEBUG] WSS request to: %s\n", ctx.Host())
	//toClose := make(chan net.Conn)
	//go ctx.copyAndClose(targetSiteConnIdle, clientConnIdle, toClose)
	//go ctx.copyAndClose(clientConnIdle, targetSiteConnIdle, toClose)
	//ctx.closeTogether(toClose)

	// Check to see if the request failed over to the local network and let the caller know.
	//errmsg := dnsbypassctx.Value(shadownetwork.ShadowTransportFailed)
	//if errmsg != nil {
	//	errmsgstruct := errmsg.(*shadownetwork.ShadowNetworkFailure)
	//	if errmsgstruct != nil {
	//		if errmsgstruct.Failed {
	//			ctx.PrivateNetwork = false
	//		}
	//	}
	//}


	return nil
}

// Returns a DNS dialer which can bypass local DNS
func HijackedDNSDialer() (*net.Dialer) {
	dnsclient := new(dns.Client)

	proxy := dns.NameServers{
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53},
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54},
	}.Upstream(rand.Reader)

	dnsclient.Transport = &dns.Transport{
		Proxy: proxy,
	}

	// This is a http/s dialer with a custom DNS resolver.
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: dnsclient.Dial,
		},
	}

	return dialer
}

// Forwards a request to a downstream server. This is done after MITM has been established.
// TODO: Remove host from function parameters
func (ctx *ProxyCtx) ForwardRequest(host string) error {

	// If the request was whitelisted, then use the upstream DNS.
	dnsbypassctx := ctx.Req.Context()
	if ctx.Whitelisted {
		//ctx.Logf(1, "  *** ForwardRequest() - Bypassing DNS for whitelisted site [%s]", ctx.host)
		dnsbypassctx = context.WithValue(ctx.Req.Context(), dns.UpstreamKey, 0)
	}

	// Send in a pointer to a struct that RoundTrip can modify to let us know if there was an error calling out to the private network
	dnsbypassctx = context.WithValue(dnsbypassctx, shadownetwork.ShadowTransportFailed, &shadownetwork.ShadowNetworkFailure{})

	ctx.removeProxyHeaders()

	// Requests which are proxied by AkamaiTechnologies never timeout using the usual methods. This is a fail safe.
	cancel := make(chan struct{})
	ctx.Req.Cancel = cancel

	resp, err := ctx.RoundTrip(ctx.Req.WithContext(dnsbypassctx))

	// Log RoundTrip error if one was received
	if ctx.Trace && err != nil {
		ctx.TraceInfo.RoundTripError = err.Error()
	}

	// Check to see if the request failed over to the local network and let the caller know.
	errmsg := dnsbypassctx.Value(shadownetwork.ShadowTransportFailed)
	if errmsg != nil {
		errmsgstruct := errmsg.(*shadownetwork.ShadowNetworkFailure)
		if errmsgstruct != nil {
			if errmsgstruct.Failed {
				ctx.PrivateNetwork = false
			}
		}
	}

	ctx.Resp = resp

	if err != nil {
		ctx.ResponseError = err
		return err
	}


	ctx.originalResponseBody = resp.Body
	ctx.ResponseError = nil

	return nil
}

func (ctx *ProxyCtx) writeResponseHeaders() {
	if ctx.Resp == nil {
		fmt.Println("[ERROR] No response to write headers for...")
		return
	}
	for name, headers := range ctx.Resp.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			ctx.TraceInfo.ResponseHeaders = append(ctx.TraceInfo.ResponseHeaders, fmt.Sprintf("%v: %v", name, h))
		}
	}
}

func (ctx *ProxyCtx) DispatchResponseHandlers() error {
	//fmt.Println("[DEBUG] DispatchResponseHandlers()")

	var rejected = false
	var then Next
	for _, handler := range ctx.Proxy.responseHandlers {
		//fmt.Println("[DEBUG] DispatchResponseHandlers() Loop")
		then = handler.Handle(ctx)
		//fmt.Printf("[DEBUG] DispatchResponseHandlers: %s [URL: %s]\n", then, ctx.Req.URL.Host)
		switch then {
		case DONE:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() DONE")
			if ctx.Trace {
				ctx.writeResponseHeaders()
			}
			return ctx.DispatchDoneHandlers()
		case NEXT:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() NEXT")
			continue
		case FORWARD:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() FORWARD")
			break
		case MITM:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() MITM")
			panic("MITM doesn't make sense when we are already parsing the request")
		case REJECT:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() REJECT")
			rejected = true

		case SIGNATURE:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() SIGNATURE")
			// Do nothing. We're just returning the client signature.
			//ctx.Logf(1, " *** DispatchResponseHandlers:SIGNATURE")
		default:
			//fmt.Println("[DEBUG] DispatchResponseHandlers() DEFAULT")
			panic(fmt.Sprintf("Invalid value %v for Next after calling %v", then, handler))
		}
	}

	//if ctx.Resp == nil {
	//	fmt.Println("[ERROR] DispatchResponseHandlers() - Response was nil")
	//}
	// A nil Resp means that the connection was dropped without even a status
	// code. This is typical if our DNS redirects to a closed port on this device.
	// In the case of a MITM attack, we can either drop the connection or
	// return a status 500 code.
	if ctx.Resp == nil || rejected {
		//fmt.Println("[DEBUG] DispatchResponseHandlers() Resp was nil or rejected")
		if rejected {
			// Forward a dummy file to the caller if we can tell what it is
			ext := filepath.Ext(ctx.Req.URL.Path)
			//ctx.Logf("  path: %s  extension: %s", ctx.Req.URL.Path, ext)
			switch ext {
			case ".js":
				//ctx.Logf("  Serving dummy script")
				ctx.NewEmptyScript()
			case ".png", ".gif":
				//ctx.Logf("  Serving dummy %s", ext)
				ctx.NewEmptyImage(ext)
			default:
				// Note that jpg pixels are > 1k in length and are rarely used
				// so we just return a 502 error to avoid the bandwidth.
				// Todo: Revisit this if we're seeing too many broken image icons in web pages
				// Todo: Refactor Winston specific code to the Winston package.
				//ctx.NewResponse(502, "text/plain; charset=utf-8", "502.2 Blocked by Winston [" + ext + "]")

				title := "Tracker Blocked"
				errorcode := "502.2 Blocked by Winston"
				text := "A website is attempting to track you. For your protection, access to this page has been blocked. It’s recommended that you do NOT visit this site."
				proceed := "<a href=\"#\" onclick=\"buildURL();return false;\">Visit this page anyway</a>"

				body := strings.Replace(blockedhtml, "%BLOCKED%", errorcode, 1)
				body = strings.Replace(body, "%TITLE%", title, 1)
				body = strings.Replace(body, "%TEXT%", text, 1)
				body = strings.Replace(body, "%PROCEED%", proceed, 1)
				//ctx.NewResponse(504, "text/plain; charset=utf-8", "504 Blocked by Winston / No response from server")
				ctx.NewResponse(502, "text/html; charset=utf-8", body)

				//ctx.NewResponse(502, "text/html; charset=utf-8", strings.Replace(blockedhtml, "Blocked", "502.2 Blocked by Winston", 1))

			}

			return ctx.ForwardResponse(ctx.Resp)
			//} else {
			//	http.Error(ctx.ResponseWriter, err.Error(), 500)
			//}
		} else {

			// Note: Have to send a response back or the client may hang until the browser times out.
			if len(ctx.Req.URL.String()) > 80 {
				ctx.Logf(2, "BLOCKED/NoResponse 504: %s", ctx.Req.URL.String()[:80])
			} else {
				ctx.Logf(2, "BLOCKED/NoResponse 504: %s", ctx.Req.URL)
			}


			//fmt.Printf("  *** Response error: \n", ctx.ResponseError)

			title := "Tracker Blocked"
			errorcode := "504 Blocked by Winston"
			text := "A website is attempting to track you. For your protection, access to this page has been blocked. It’s recommended that you do NOT visit this site."
			proceed := "<a href=\"#\" onclick=\"buildURL();return false;\">Visit this page anyway</a>"
			// Friendly error logging
			if ctx.ResponseError != nil {
				switch ctx.ResponseError.Error() {
				case "x509: certificate signed by unknown authority":
					title = "Website blocked"
					errorcode = "Certificate signed by unknown authority"
					text = "The certificate issued by this website was issued by an unknown authority. For your protection, access to this page has been blocked."
					proceed = ""
				default:
					title = "Network error"
					errorcode = ctx.ResponseError.Error()
					text = "This error may be temporary. It may resolve itself by refreshing the page."
					proceed = ""
				}
			}

			body := strings.Replace(blockedhtml, "%BLOCKED%", errorcode, 1)
			body = strings.Replace(body, "%TITLE%", title, 1)
			body = strings.Replace(body, "%TEXT%", text, 1)
			body = strings.Replace(body, "%PROCEED%", proceed, 1)
			//ctx.NewResponse(504, "text/plain; charset=utf-8", "504 Blocked by Winston / No response from server")
			ctx.NewResponse(504, "text/html; charset=utf-8", body)

			return ctx.ForwardResponse(ctx.Resp)
		}

		//ctx.Logf("  Dispatching Done Handlers")
		ctx.DispatchDoneHandlers()
		return nil
	}

	if ctx.Trace {
		ctx.writeResponseHeaders()
	}

	//fmt.Println("[DEBUG] DispatchResponseHandlers() Calling ForwardResponse...")
	ret := ctx.ForwardResponse(ctx.Resp)

	return ret
}

func (ctx *ProxyCtx) DispatchDoneHandlers() error {
	var then Next
	for _, handler := range ctx.Proxy.doneHandlers {
		then = handler.Handle(ctx)

		switch then {
		case DONE:
			return nil
		case NEXT:
			continue
		case FORWARD:
			break
		case MITM:
			panic("MITM doesn't make sense when we are done")
		case REJECT:
			panic("REJECT a response ? then do what, send a 500 back ?")
		case SIGNATURE:
			//ctx.Logf(1, "  *** DispatchDoneHandlers:SIGNATURE")
			return nil
		default:
			// We're done
			return nil
		}
	}

	return nil
}

func (ctx *ProxyCtx) ForwardResponse(resp *http.Response) error {


	if ctx.IsThroughMITM && ctx.IsSecure {
		return ctx.forwardMITMResponse(ctx.Resp)
	}

	w := ctx.ResponseWriter

	//ctx.Logf("Copying response to client [%s] %v [%d]", ctx.Host(), resp.Status, resp.StatusCode)

	// http.ResponseWriter will take care of filling the correct response length
	// Setting it now, might impose wrong value, contradicting the actual new
	// body the user returned.
	// We keep the original body to remove the header only if things changed.
	// This will prevent problems with HEAD requests where there's no body, yet,
	// the Content-Length header should be set.

	if ctx.originalResponseBody != resp.Body {
		if ctx.NewBodyLength == 0 {
			resp.Header.Del("Content-Length")
			//resp.Header.Set("Transfer-Encoding", "chunked")
		} else {
			//ctx.Logf("  *** Setting new content length: %d", ctx.NewBodyLength)
			resp.Header.Set("Content-Length", strconv.Itoa(ctx.NewBodyLength))
		}

		//resp.Header.Del("Content-Length")
	}

	// Identify ourselves to the browser. Useful for debugging purposes.
	resp.Header.Set("Server", "Winston")


	if len(ctx.StatusMessage) != 0 {
		for _, msg := range(ctx.StatusMessage) {
			resp.Header.Add("Winston-Status", msg)
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// TODO: This is a performance bottleneck
	io.Copy(w, resp.Body)

	// The response body must always be open at this point, so we close it.
	if err := resp.Body.Close(); err != nil {
		ctx.Warnf("Can't close response body %v", err)
	}

	ctx.DispatchDoneHandlers()

	return nil
}

// RLS: 8/14/2017 - Added support for Content Length instead of chunking. To use, set the ctx.NewBodyLength property.
func (ctx *ProxyCtx) forwardMITMResponse(resp *http.Response) error {
	// Make sure we close the original response body to prevent memory leaks. This has to be
	// done no matter what.
	defer resp.Body.Close();


	text := resp.Status
	//fmt.Printf("[DEBUG] forwardMITMResponse()  Status: %s", text)
	if ctx.Trace {
		fmt.Printf("[TRACE] Response protocol: %s\n", resp.Proto)
	}
	statusCode := strconv.Itoa(resp.StatusCode) + " "
	if strings.HasPrefix(text, statusCode) {
		text = text[len(statusCode):]
	}
	// always use 1.1 to support chunked encoding
	if _, err := io.WriteString(ctx.Conn, "HTTP/1.1"+" "+statusCode+text+"\r\n"); err != nil {
		fmt.Printf("[ERROR] Cannot write TLS response HTTP status from mitm'd client [%s]: %v\n", ctx.Host(), err)
		return err
	}

	// Force connection close otherwise chrome will keep CONNECT tunnel open forever
	// https://github.com/elazarl/goproxy/issues/209
	resp.Header.Set("Connection", "close")

	if ctx.NewBodyLength == 0 {
		resp.Header.Del("Content-Length")
		resp.Header.Set("Transfer-Encoding", "chunked")
	} else {
		//ctx.Logf("  *** Setting new content length: %d", ctx.NewBodyLength)
		resp.Header.Set("Content-Length", strconv.Itoa(ctx.NewBodyLength))
	}

	if len(ctx.StatusMessage) != 0 {
		for _, msg := range(ctx.StatusMessage) {
			resp.Header.Add("Winston-Status", msg)
			//ctx.Logf(1, "  *** %s", msg)
		}
	}

	// Identify ourselves to the client. Useful for debugging purposes.
	resp.Header.Set("Server", "Winston")

	if err := resp.Header.Write(ctx.Conn); err != nil {
		ctx.Warnf("Cannot write TLS response header from mitm'd client: %v", err)
		return err
	}
	if _, err := io.WriteString(ctx.Conn, "\r\n"); err != nil {
		ctx.Warnf("Cannot write TLS response header end from mitm'd client: %v", err)
		return err
	}

	if ctx.NewBodyLength == 0 {
		// Chunk the body back to the caller
		chunked := newChunkedWriter(ctx.Conn)

		// This reads the body into the writer
		if _, err := io.Copy(chunked, resp.Body); err != nil {
			ctx.Warnf("Cannot write TLS response body from mitm'd client: %v / host: %s", err, ctx.host)
			return err
		}
		if err := chunked.Close(); err != nil {
			ctx.Warnf("Cannot write TLS chunked EOF from mitm'd client: %v", err)
			return err
		}
	} else {
		// We set the content-length so stream it back
		//ctx.Logf("  *** Found target NewBodyLength: %d url %+s\n\n%s\n\n", ctx.NewBodyLength, ctx.Req.URL.String(), ctx.Resp.Body)
		body, err := ioutil.ReadAll(resp.Body);

		if err != nil {
			ctx.Warnf("Could not read TLS response body from mitm'd client: %v", err)
			return err
		}
		if _, err := ctx.Conn.Write(body); err != nil {
			ctx.Warnf("Cannot write fixed length TLS response from mitm'd client: %v", err)
			return err
		}
	}

	if _, err := io.WriteString(ctx.Conn, "\r\n"); err != nil {
		ctx.Warnf("Cannot write TLS response chunked trailer from mitm'd client: %v", err)
		return err
	}

	ctx.DispatchDoneHandlers()

	return nil
}

// BufferResponse reads the whole Resp.Body and returns a byte array.
// It is the caller,s responsibility to set a new Body with
// `SetResponseBody` afterwards.  Otherwise, the Resp.Body will be in
// a closed state and that is not fun for other parts of your program.
// This replaces the need for goproxy's previous `HandleBytes`
// implementation.
func (ctx *ProxyCtx) BufferResponse() ([]byte, error) {
	if ctx.Resp == nil {
		return nil, fmt.Errorf("Response is nil")
	}

	b, err := ioutil.ReadAll(ctx.Resp.Body)
	if err != nil {
		ctx.Warnf("error 35 reading response: %s", err)
		return nil, err
	}
	ctx.Resp.Body.Close()

	return b, nil
}

// SetResponseBody overwrites the Resp.Body with the given content.
// It is the caller's responsibility to ensure the previous Body was
// read and/or closed properly. Use `BufferResponse()` for that. This
// call will fail if ctx.Resp is nil.
func (ctx *ProxyCtx) SetResponseBody(content []byte) {
	if ctx.Resp == nil {
		ctx.Warnf("failed to SetResponseBody, the Response is nil")
		return
	}
	ctx.Resp.Body = ioutil.NopCloser(bytes.NewBuffer(content))
}

func (ctx *ProxyCtx) NewResponse(status int, contentType, body string) {
	ctx.Resp = NewResponse(ctx.Req, status, contentType, body)
}

func (ctx *ProxyCtx) NewTextResponse(body string) {
	ctx.Resp = NewResponse(ctx.Req, http.StatusAccepted, "text/plain", body)
}

func (ctx *ProxyCtx) NewHTMLResponse(body string) {
	ctx.Resp = NewResponse(ctx.Req, http.StatusAccepted, "text/html", body)
}

// Returns an empty script. This is done to be less obvious
// that we blocked it.
func (ctx *ProxyCtx) NewEmptyScript() {
	ctx.Resp = NewResponse(ctx.Req, http.StatusBadGateway, "application/javascript; charset=utf-8", "/*Blocked by Winston*/")

	// This allows the injected javascript to see the contents of this script block
	//ctx.Resp.Header.Add("Access-Control-Allow-Origin", "*")
}

func (ctx *ProxyCtx) NewEmptyImage(extension string) {
	//ctx.Logf(2, "NewEmptyImage [%s]", ctx.Host())
	switch extension {
	case ".gif":
		ctx.NewEmptyGif()
	case ".png":
		ctx.NewEmptyPng()
	default:
		// Don't know what it is... send back a gif.
		ctx.NewEmptyGif()
	}
}

// Returns 1x1 empty gif. Useful for suppressing broken image icons.
// 9/19/2017 - Now returns 403 so we can detect blocked images on the client side.
const base64GifPixel = "R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs="
func (ctx *ProxyCtx) NewEmptyGif() {
	//ctx.Logf("NewEmptyGif: ...")
	//output,_ := base64.StdEncoding.DecodeString(base64GifPixel)

	// Note: Chrome will not fire an error if data is returned along with an error code.
	// In order to detect blocked images on the client side, we cannot send any data.
	//ctx.Resp = NewResponse(ctx.Req, http.StatusNotFound, "image/gif", string(output))
	ctx.Resp = NewResponse(ctx.Req, http.StatusForbidden, "text/html", "Blocked by Winston")
}

// Returns 1x1 empty png. Useful for suppressing broken image icons.
const base64PngPixel = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVQYV2P4DwABAQEAWk1v8QAAAABJRU5ErkJggg=="
func (ctx *ProxyCtx) NewEmptyPng() {
	//ctx.Logf("NewEmptyGif: ...")
	//output,_ := base64.StdEncoding.DecodeString(base64PngPixel)
	//ctx.Resp = NewResponse(ctx.Req, http.StatusNotFound, "image/png", string(output))
	ctx.Resp = NewResponse(ctx.Req, http.StatusForbidden, "text/html", "Blocked by Winston")
}

func (ctx *ProxyCtx) tlsConfig(host string) (*tls.Config, error) {
	ca := ctx.Proxy.MITMCertConfig
	if ctx.MITMCertConfig != nil {
		ca = ctx.MITMCertConfig
	}

	// Ensure that the certificate for the target site has been generated
	err := ca.cert(host)
	if err != nil {
		fmt.Printf("[DEBUG] Certificate signing error [%s] %+v\n", host, err)
		ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
		return nil, err
	}
	// Hook the certificate chain verification
	ca.Config.VerifyPeerCertificate = ca.VerifyPeerCertificate
	return ca.Config, nil
}

// Test function to see if we can read the CLIENTHELLOINFO containing the client's
// supported cipher protocols.
/*
func (ctx *ProxyCtx) getCertificateHook(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	//fmt.Printf("  *** getCertificateHook()... Suites: \n  *** ")
	var b bytes.Buffer

	for _, suite := range helloInfo.CipherSuites {

		b.Write([]byte (strconv.Itoa(int(suite))))

	}
	// attach buffer to ctx
	ctx.CipherSignature = string(b.Bytes())

	// print it out
	//fmt.Printf("  *** Cipher signature: %v \n", ctx.CipherSignature)

	return nil, nil
}
*/

func (ctx *ProxyCtx) removeProxyHeaders() {
	r := ctx.Req
	r.RequestURI = "" // this must be reset when serving a request with the client

	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")

	// curl can add that, see
	// http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")

	// Connection is single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	r.Header.Del("Connection")
}

func (ctx *ProxyCtx) httpError(parentErr error) {
	ctx.Logf(6, "WARN: Sending http error: %s", parentErr)

	if !ctx.sniffedTLS {
		if _, err := io.WriteString(ctx.Conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n"); err != nil {
			ctx.Warnf("Error responding to client: %s", err)
		}
	}
	if err := ctx.Conn.Close(); err != nil {
		ctx.Warnf("Error closing client connection: %s", err)
	}
}

// RLS 9/13/2017 - Alternate method to prevent memory leaks when connections are unexpectedly closed.
func (ctx *ProxyCtx) copyAndClose(w, r net.Conn, toClose chan net.Conn) {
	// Idle timeout - designed to close connections after 60 seconds of no activity
	ridle := &IdleTimeoutConn{Conn: r}
	widle := &IdleTimeoutConn{Conn: w}

	// This timeout is a sanity check simply designed to close connections after 5 minutes.
	timeoutDuration := 300 * time.Second
	ridle.SetReadDeadline(time.Now().Add(timeoutDuration))
	widle.SetWriteDeadline(time.Now().Add(timeoutDuration))

	//start := time.Now()
	bytes, err := io.Copy(widle, ridle)
	//fmt.Printf("[DEBUG] CopyAndClose - wrote %d bytes err=%+v\n", bytes,err)
	if err != nil && bytes <= 0 {
		ctx.Warnf("Error copying to client [%s]", ctx.Host(), err)
	}
	toClose <- ridle
	//toClose <- widle
}

func (ctx *ProxyCtx) closeTogether(toClose chan net.Conn) {
	c1 := <-toClose
	c2 := <-toClose
	if err := c1.Close(); err != nil {
		ctx.Warnf("Error closing connection: %s", err)
	}
	if err := c2.Close(); err != nil {
		ctx.Warnf("Error closing connection: %s", err)
	}
}

// These timeouts represent the maximum time a connection can be open. They are in addition to the
// standard 60 second idle timeout.
const serverReadTimeout = 15 * 60	// response timeout in seconds
const clientReadTimeout = 15 * 60	// Client request timeout in seconds

// RLS 9/6/2018 - Cleaner method to pipe two conns together.
// Fuse connections together. Have to take precautions to close connections down in various cases.
// 9/16/2018 - Requests which are proxied by static.deploy.akamaitechnologies.com and a few other sites hang here forever.
// It's unclear why this is happening but we've been able to reproduce the fact that the timeouts are not honored in these
// cases. To ensure these connections close down, callers should set and close the Request.Cancel channel after some time limit.
func fuse(client, backend net.Conn, debug string) {
	// Copy from client -> backend, and from backend -> client
	//defer p.logConnectionMessage("closed", client, backend)
	//p.logConnectionMessage("opening", client, backend)

	defer client.Close()
	defer backend.Close()

	// Pipes data from the remote server to our client
	backenddie := make(chan struct{})
	go func() {
		backend.SetReadDeadline(time.Now().Add(serverReadTimeout * time.Second))

		// Wrap the backend connection so that we can enforce an idle timeout.
		idleconn := &IdleTimeoutConn{Conn: backend}

		//n, err :=
		copyData(client, idleconn)
		// These errors are common with streaming sites. Uncomment to see.
		//if err != nil && !strings.Contains(err.Error(), "closed network connection") {
		//	fmt.Printf("[ERROR] ctx.go/fuse() error backend->client: %d bytes transferred. [%s] Err=%s\n", n, debug, err)
		//}

		close(backenddie)
	}()

	// Pipes data from our client to the remote server
	clientdie := make(chan struct{})
	go func() {
		// Set read timeout
		// With HTTP/S requests, we expect these to complete quickly. However, websockets and other protocols
		// may need to keep the connection open more or less indefinitely.
		client.SetReadDeadline(time.Now().Add(clientReadTimeout * time.Second))

		// Wrap the backend connection so that we can enforce an idle timeout.
		idleconn := &IdleTimeoutConn{Conn: client}

		// n, err :=
		copyData(backend, idleconn)

		// Timeouts and connection reset errors are very common, especially with Netflix.
		// Uncomment to see these... not particularly helpful in most cases though.
		//if err != nil && !strings.Contains(err.Error(), "timeout") {
		//	fmt.Printf("[ERROR] ctx.go/fuse() error client->backend: %d bytes transferred. [%s] Err=%s\n", n, debug, err)
		//}

		close(clientdie)
	}()

	// Wait for both connections to close before shutting the tunnel down. Otherwise we can end up
	// in a race condition where the client request ends and shuts the tunnel down.
	<-backenddie
	<-clientdie

}


// Copy data between two connections
func copyData(dst net.Conn, src net.Conn) (int64, error) {
	defer dst.Close()
	defer src.Close()

	n, err := io.Copy(dst, src)

	//if err != nil {
	//	fmt.Printf("fuse error: %d bytes copied.\n", n)
	//}

	return n, err

}



var charsetFinder = regexp.MustCompile("charset=([^ ;]*)")

// Will try to infer the character set of the request from the headers.
// Returns the empty string if we don't know which character set it used.
// Currently it will look for charset=<charset> in the Content-Type header of the request.
func (ctx *ProxyCtx) Charset() string {
	charsets := charsetFinder.FindStringSubmatch(ctx.Resp.Header.Get("Content-Type"))
	if charsets == nil {
		return ""
	}
	return charsets[1]
}

func copyHeaders(dst, src http.Header) {
	for k := range dst {
		dst.Del(k)
	}
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isEof(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	if err == io.EOF {
		return true
	}
	return false
}

// TODO: Refactor this to its own file
var blockedhtml = `
<!DOCTYPE html><html lang="en">
<head>
    <title>Page blocked by Winston</title>

    <style>
        html, body {
            height:100%;
			width:100%;
            margin:0;
            padding:0;
			font-family: 'IBM Plex Mono';
        }
        .wrap {
            display:table;
			table-layout: fixed;
            width: 100%;
			height: 100%;
        }
        .image {
			text-align: center;
            vertical-align:middle;
            display:table-cell;


        }
	.reason {
	    width:500px;
            vertical-align:middle;
	    text-align: left;
            display:table-cell;
	    padding: 0px 20px;
	    font-size:14px;
	}
	.spacer {
		min-width:20px;
		display:table-cell;

	}
        .image img {
            max-width: 250px;
            height:auto;
        }
	h1 { font-size: 28px; }
	@media (max-width: 750px) {
		.image { display:none;}
		.middle { width:100% !important; }
		.spacer { display:none; }
		.reason {width: 100%;}
	}

	@media (max-width: 1000px) {
		.image { width:250px; }
		.middle { width:calc(100% - 250px) !important; }
		.spacer { display:none; }
	}
    </style>
 <script>
   function post(url, params, callback) {
      var httpRequest = new XMLHttpRequest();
      httpRequest.onreadystatechange = function () {
        if (this.readyState != 4) return;

        if (this.status == 200) {
          if (callback) {
            callback(this.responseText);
          }
        }
      };
      httpRequest.open('POST', url);
      httpRequest.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

      httpRequest.send(JSON.stringify(params));
  }

function buildURL() {
    var hostname;
    //find & remove protocol (http, ftp, etc.) and get hostname
	url = window.location.href;

    if (url.indexOf("://") > -1) {
        hostname = url.split('/')[2];
    }
    else {
        hostname = url.split('/')[0];
    }

    hostname = hostname.split(':')[0];
    hostname = hostname.split('?')[0];

	var scheme = "http://winston.conf:81";
	if (location.protocol == "https:")
	    scheme = "https://winston.conf:82";

	var url = scheme + '/api/add_allowed_site';
	var reqdata = {Host: hostname, Minutes: 10};
	post(url, reqdata, function (data) {
		location.reload(true);
	});

}
 </script>
</head>
<body>
<div class="wrap">
        <div class="image">
			<img src="//winston.conf/images/logo.svg">
            <div>%BLOCKED%</div>
        </div>
		<div class="reason">

			<h1>%TITLE%</h1>

			<p>%TEXT%</p>

<p>%PROCEED%</p>
		</div>
		<div class="spacer"></div>

</div>

</body>
</html>`
