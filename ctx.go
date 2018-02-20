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
//	"time"
	"github.com/inconshreveable/go-vhost"
//	"encoding/base64"
	"path/filepath"
//	"net/http/httputil"
//	"net/url"
	"time"
//	"encoding/binary"
	"net/textproto"
	"sync"
	"context"
	"github.com/benburkert/dns"
)

// ProxyCtx is the Proxy context, contains useful information about every request. It is passed to
// every user function. Also used as a logger.
type ProxyCtx struct {
	Method          string
	SourceIP        string
	IsSecure        bool // Whether we are handling an HTTPS request with the client
	IsThroughMITM   bool // Whether the current request is currently being MITM'd
	IsThroughTunnel bool // Whether the current request is going through a CONNECT tunnel, doing HTTP calls (non-secure)

	// Sniffed and non-sniffed hosts, cached here.
	host    string
	sniHost string

	sniffedTLS     bool
	MITMCertConfig *GoproxyConfig

	connectScheme string

	// OriginalRequest holds a copy of the request before doing some HTTP tunnelling
        // through CONNECT, or doing a man-in-the-middle attack.
	OriginalRequest *http.Request

	// Contains the request and response streams from the proxy to the
        // downstream server in the case of a MITM connection
	Req            *http.Request
	ResponseWriter http.ResponseWriter

	// Connections, up (the requester) and downstream (the server we forward to)
	Conn           net.Conn
	targetSiteConn net.Conn // used internally when we established a CONNECT session,
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
	RoundTripper       RoundTripper
	fakeDestinationDNS string

	// HAR logging
	isLogEnabled     bool
	isLogWithContent bool

	// will contain the recent error that occured while trying to send receive or parse traffic
	Error error

	// UserObjects and UserData allow you to keep data between
	// Connect, Request and Response handlers.
	UserObjects map[string]interface{}
	UserData    map[string]string

	// Will connect a request to a response
	Session int64
	proxy   *ProxyHttpServer

	// Closure to alert listeners that a TLS handshake failed
	// RLS 6-29-2017
	Tlsfailure func(ctx *ProxyCtx, untrustedCertificate bool)

	// References to persistent caches for statistics collection
	// RLS 7-5-2017
	UpdateAllowedCounter func()
	UpdateBlockedCounter func()
	UpdateBlockedCounterByN func(int)
	UpdateBlockedHostsByN func(string, int)

	// Client signature
	// https://blog.squarelemon.com/tls-fingerprinting/
	CipherSignature string

	NewBodyLength int
	VerbosityLevel uint16

	// 11/2/2017 - Used for replacement macros (user agents)
	DeviceType int

	// 2/16/2018 - Whitelist flag. If set, response filtering will be turned off and the
	// local DNS will be bypassed. This allows the resource to run as originally intended
	// (privacy leaks and all).
	Whitelisted bool

	// Keeps a list of any messages we want to pass back to the client
	StatusMessage []string
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

func (ctx *ProxyCtx) getConnectScheme() string {
	if ctx.connectScheme == "" {
		if strings.HasSuffix(ctx.host, ":80") {
			return "http"
		} else {
			return "https"
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

// ManInTheMiddle triggers either a full-fledged MITM when done through HTTPS, otherwise, simply tunnels future HTTP requests through the CONNECT stream, dispatching calls to the Request Handlers
func (ctx *ProxyCtx) ManInTheMiddle() error {
	if ctx.Method != "CONNECT" {
		panic("method is not CONNECT")
	}

	if ctx.getConnectScheme() == "http" {
		return ctx.TunnelHTTP()
	} else {
		return ctx.ManInTheMiddleHTTPS()
	}
}

// TunnelHTTP assumes the current connection is a plain HTTP tunnel,
// with no security. It then dispatches all future requests in there
// through the registered Request Handlers.
//
// Requests flowing through this tunnel will be marked `ctx.IsThroughTunnel == true`.
//
// You can also find the original CONNECT request in `ctx.OriginalRequest`.
func (ctx *ProxyCtx) TunnelHTTP() error {
	if ctx.Method != "CONNECT" {
		panic("method is not CONNECT")
	}

	if !ctx.sniffedTLS {
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}

	//if strings.Contains(ctx.host, "js-agent.newrelic.com") {
	//	ctx.Logf(2, "  *** newrelic - TunnelHTTP")
	//}

	//ctx.Logf("Assuming CONNECT is plain HTTP tunneling, mitm proxying it")
	targetSiteConn, err := ctx.proxy.connectDial("tcp", ctx.host)
	if err != nil {
		ctx.Warnf("Error dialing to %s: %s", ctx.host, err.Error())
		return err
	}

	ctx.OriginalRequest = ctx.Req
	ctx.targetSiteConn = targetSiteConn
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

	for {
		client := bufio.NewReader(ctx.Conn)
		req, err := http.ReadRequest(client)
		if err != nil && err != io.EOF {
			ctx.Warnf("cannot read request of MITM HTTP client: %+#v", err)
		}
		if err != nil {
			return err
		}

		ctx.Req = req
		ctx.IsThroughTunnel = true

		ctx.proxy.dispatchRequestHandlers(ctx)
	}

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
			ctx.Logf(1, "Error (1): Panic while processing MITM request. Recovering gracefully.", r)
		}
	}()

	if ctx.Method != "CONNECT" {
		panic("method is not CONNECT")
	}

	// Use to debug non-SNI requests
	isIpAddress := validIP4(ctx.host)

	// If we haven't already sniffed, send a 200 OK back to the client
	if !ctx.sniffedTLS {
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

	// RLS 2/16/2018
	// TODO: Should we fetch downstream certificates and copy their properties to our local certificate?
	// This might improve compatibility as some sites return multiple hostnames in their cert.
	tlsConfig, err := ctx.tlsConfig(signHost)

	// We should always be able to get a certificate when a signhost has been provided
	if !isIpAddress && err != nil {
		ctx.Logf(1, "ManInTheMiddleHTTPS - Couldn't configure MITM TLS tunnel: %s", err)
		ctx.httpError(err)
		return err
	}


	// If no SNI host was provided, try to spoof the destination and generate a certificate
	// for future requests.
	// Note: This was a dumb idea. This mainly happens with smart devices. They don't
	// trust our CA and there's no way to make them. We just have to whitelist them.
	if isIpAddress && err != nil  {

		if ctx.Tlsfailure != nil {
			//ctx.Logf(2, "  *** TLS Failure (IP Address)")
			ctx.Tlsfailure(ctx, false)
		}

		// We were given an IP address, which is typical of non-SNI requests
		// We have to go get the certificate and retrieve the organization name
		// from it in order to generate a proper certificate. This should be
		// cached so it only needs to be done once for each IP lookup.

		// We don't want to block, so for now just spin up a thread and see
		// if we can get the certificate from the remote server.
		go func() {
			//ctx.Logf("  *** ManInTheMiddleHTTPS - Initiating non-SNI certificate generation routine: %s", ctx.host)

			// Dial the destination
			conn, _ := tls.Dial("tcp", ctx.host, &tls.Config{InsecureSkipVerify: true})
			defer conn.Close()

			// Check if an error was received. If so, drop the connection.
			//if err != nil {
			//	ctx.Logf("  *** Couldn't connect to destination [%s]", ctx.host)
			//}

			// See if we have the cert
			//ctx.Logf(" Do I have a certificate? %v", conn.ConnectionState().PeerCertificates[0])
			//ctx.Logf("   Do I have a common name? %s", conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
			//tlsconn.ConnectionState().PeerCertificates[0].Subject.CommonName
			commonName := conn.ConnectionState().PeerCertificates[0].Subject.CommonName

			// Create a certificate using the IP/hostname pair and cache it
			ca := ctx.proxy.MITMCertConfig

			if ctx.MITMCertConfig != nil {
				ca = ctx.MITMCertConfig
			}

			// This method creates a certificate for the given IP address
			certErr := ca.certWithCommonName(ctx.host, commonName)

			if certErr != nil {
				ctx.Warnf("Cannot sign host certificate with provided CA: %s", certErr)
				return
			}

			// Kill the connection, we got what we've needed
			// conn.Close()


		}()

		// The first request will abort...
		//ctx.Logf("  *** Exiting non-SNI certificate generation routine")

		return err
	}


	// This contains the original connection with the client
	ctx.OriginalRequest = ctx.Req

	// this goes in a separate goroutine, so that the net/http server won't think we're
	// still handling the request even after hijacking the connection. Those HTTP CONNECT
	// request can take forever, and the server will be stuck when "closed".
	// TODO: Allow Server.Close() mechanism to shut down this connection as nicely as possible
	go func() {
		// Found a rare but irreproducible race condition when calling isEof() with many
		// active connections at the same time. This ensures that only the active connection
		// goes down and doesn't take the entire process with it.
		/*defer func() {
			if r := recover(); r != nil {
				ctx.Logf(1, "Error (2): Panic while processing MITM request. Recovering gracefully.", r)
			}
		}()*/

		// If we make it here, then we are responsible for closing the client connection
		defer ctx.Conn.Close()

		//TODO: cache connections to the remote website
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
		defer rawClientTls.Close()

		// Performs the TLS handshake
		if err := rawClientTls.Handshake(); err != nil {
			// A handshake error typically only occurs on the client side
			// when pinned Certificates are being used, ie: a mobile
			// application refuses to trust our local CA. We need to
			// determine if the target site would have been blocked by
			// our DNS server. If it would have gone through, then we
			// should let listeners know that we've found a domain that
			// should probably be whitelisted.

			ctx.Logf(1, "Cannot handshake client %v %v", r.Host, err)

			// Is anyone listening? Let them know the TLS handshake failed.
			if ctx.Tlsfailure != nil {
				//ctx.Logf(2, "  *** TLS Failure (Handshake error)")
				ctx.Tlsfailure(ctx, true)
			}

			return
		}

		ctx.Conn = rawClientTls
		ctx.IsSecure = true

		clientTlsReader := bufio.NewReader(rawClientTls)
		gotSomething := false

		// Use to detect timeouts
		start := time.Now()

		count := 0
		// Chrome will hang CONNECT requests. This is fixed by sending "connection:close"
		// header in the response to the client.
		// TODO: some requests still hang indefinitely. Implement a timeout.


		for !isEof(clientTlsReader) {
			count = count + 1

			// Use this debug code to read the TLS request
			/*if strings.Contains(ctx.host, "js-agent.newrelic.com") {
				ctx.Logf(1, "  *** js-agent.newrelic.com request %d", count)

				/*
				tp := newTextprotoReader(clientTlsReader)
				//req = new(Request)


				// First line: GET /index.html HTTP/1.0
				var s string
				linecount := 0
				for linecount < 10 {
					if s, err = tp.ReadLine(); err != nil {
						ctx.Logf(1, " *** joinme read error: %+v", err)
					}
					ctx.Logf(1, " *** joinme : %s", s)
					linecount++
				}

			}*/

			// This reads a normal "GET / HTTP/1.1" request from the tunnel, as it thinks its
			// talking directly to the server now, not to a proxy.
			subReq, err := http.ReadRequest(clientTlsReader)

			if err != nil {
				//ctx.Warnf("MandInTheMiddleHTTPS: error reading next request: %s", err)
				// TODO: Many sites (outlook.office.com, client-channel.google.com, lync.com, etc)
				// utilize custom SSL protocols which don't conform to web request standards.
				// For instance, join.me sends "IRVPROTO" as the first line instead of the usual
				//    GET /index.html HTTP/1.1
				// These sites have to be auto whitelisted or they'll be blocked.
				//if count != 2 {
				ctx.Logf(1, "  *** TLS Protocol Error %d [%s] +%v", count, ctx.host, err.Error())

				if ctx.Tlsfailure != nil {
					if strings.Contains(err.Error(), "malformed HTTP") {
						ctx.Tlsfailure(ctx, false)
					} else if strings.Contains(err.Error(), "unknown certificate") {
						ctx.Tlsfailure(ctx, true)
					}
				}
				//}
				return //errors.New("Non-HTTP protocol detected in TLS packet. Whitelisted domain. Try again.")
			}

			gotSomething = true

			subReq.URL.Scheme = "https"
			subReq.URL.Host = ctx.host
			subReq.RemoteAddr = r.RemoteAddr // since we're converting the request, need to carry over the original connecting IP as well

			//if isIpAddress  {
			//	data, _ := httputil.DumpRequestOut(subReq, true)

			//}

			// if ctx.proxy.Verbose {
			// 	data, _ := httputil.DumpRequestOut(subReq, true)
			// 	ctx.Logf("MITM request:\n%s", string(data))
			// }

			ctx.Req = subReq
			ctx.IsThroughMITM = true

			//if isIpAddress {
			//	ctx.Logf("  *** ManInTheMiddleHTTPS (Sling) - Dispatching request handlers...")
			//}

			ctx.proxy.dispatchRequestHandlers(ctx)

			// Force a timeout. Some requests hang forever because they never send an EOF.
			end := time.Now()
			duration := end.Sub(start) / time.Millisecond
			if count > 1 {
				ctx.Logf(1, "*** clientTlsReader %d %dms [%s]", count, duration, ctx.host)
			}
			//if duration > 10000 {
			//	ctx.Logf(1, "*** Timeout %d %dms [%s]", count, duration, ctx.host)
			//	return
			//}

		}


		//if gotSomething {
		//	ctx.Logf(1, "*** clientTlsReader - out of loop")
		//}
		// We automatically whitelist all ip addresses because these are very likely to
		// be associated with streaming services.
		if !gotSomething || isIpAddress {
			//ctx.Logf("Client dropped connection. Checking TLS Failure stats... [%s]", ctx.Req.URL)

			// Note: Some websites (google in particular) send HTTPS requests as keep alives
			// and don't close them. They end up timing out. We don't want to whitelist these.
			// In contrast, smart devices and TVs close the connection immediately when they
			// don't trust the certificate. We'll use this here to prevent whitelisting
			// keep alive requests while detecting smart devices that should be tunnelled.

			end := time.Now()
			duration := end.Sub(start) / time.Millisecond

			if duration < 30 || isIpAddress {
				//if ctx.proxy.CheckTLSFailure(signHost) {
					ctx.Logf(6, "WARN: Client dropped connection or IP address detected. Whitelisting this device... [%s]", ctx.Req.URL)

					// whitelist certain sites across an entire network.
					if ctx.Tlsfailure != nil {
						ctx.Logf(2, "  *** TLS Failure (client dropped connection) [%s]", ctx.host)
						ctx.Tlsfailure(ctx, false)
					}
				//}
			} else {
				//ctx.Logf("  *** Client was dropped. Not whitelisting. [%s]", ctx.Req.URL)
			}
		}
	}()

	return nil
}

/* Debugging code for TLS handshaking code */

var textprotoReaderPool sync.Pool

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
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}

	return ctx.Conn
}

func (ctx *ProxyCtx) ForwardConnect() error {
	if ctx.Method != "CONNECT" {
		return fmt.Errorf("Method is not CONNECT")
	}

	// TODO: Should we allow forwarded requests request to bypass DNS?
	var dnsbypassctx context.Context

	targetSiteConn, err := ctx.proxy.connectDialContext(dnsbypassctx, "tcp", ctx.host)
	if err != nil {
		ctx.httpError(err)
		return err
	}

	if !ctx.sniffedTLS {
		ctx.Conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
	}

	// RLS 9/13/2017 - These are closed together because they run in different goroutines.
	// This ensures that closing one doesn't cause the other https connection to abort.
	// See: https://github.com/elazarl/goproxy/pull/161
	// Still slowly leaking memory with Abourget's code.

	toClose := make(chan net.Conn)
	go ctx.copyAndClose(targetSiteConn, ctx.Conn, toClose)
	go ctx.copyAndClose(ctx.Conn, targetSiteConn, toClose)
	go ctx.closeTogether(toClose)


	//ctx.Logf(4, "  *** ForwardConnect: Completed copy [%s]", ctx.host)

	/*go ctx.copyAndClose(targetSiteConn.(*net.TCPConn), ctx.Conn.(*net.TCPConn))
	go ctx.copyAndClose(ctx.Conn.(*net.TCPConn), targetSiteConn.(*net.TCPConn))
*/
	return nil
}

var hasPort = regexp.MustCompile(`:\d+$`)

func (ctx *ProxyCtx) RejectConnect() {
	if ctx.Method != "CONNECT" {
		panic("cannot RejectConnect() when Method is not CONNECT")
	}


	// we had support here for flushing the Response when ctx.Resp was != nil.
	// this belongs to an upper layer, not down here.  Have your code do it instead.
	if !ctx.sniffedTLS {
		ctx.Conn.Write([]byte("HTTP/1.0 502 Rejected\r\n\r\n"))
	}

	ctx.Conn.Close()
}

// Request handling

func (ctx *ProxyCtx) ForwardRequest(host string) error {
	// FIXME: we don't even use `host` here.. what's the point ?
	//ctx.Logf("Sending request %v %v with Host header %q", ctx.Req.Method, ctx.Req.URL.String(), ctx.Req.Host)

	// If the request was whitelisted, then use the upstream DNS.
	dnsbypassctx := ctx.Req.Context()
	if ctx.Whitelisted {
		//ctx.Logf(3, "OK Bypassing DNS for whitelisted referrer [%s]", ctx.host)
		dnsbypassctx = context.WithValue(ctx.Req.Context(), dns.UpstreamKey, 0)
	}

	ctx.removeProxyHeaders()
	resp, err := ctx.RoundTrip(ctx.Req.WithContext(dnsbypassctx))
	//resp, err := ctx.RoundTrip(ctx.Req)
	ctx.Resp = resp
	if err != nil {
		ctx.ResponseError = err
		return err
	}


	//if strings.Contains(ctx.Req.Host, "static.chartbeat.com") {

	//	ctx.Logf(2, "  *** Chartbeat Response IP: %s", resp.RemoteAddr)
	//}

	ctx.originalResponseBody = resp.Body
	ctx.ResponseError = nil
	//ctx.Logf("Received response %v", resp.Status)
	return nil
}

func (ctx *ProxyCtx) DispatchResponseHandlers() error {
	var rejected = false

	var then Next
	for _, handler := range ctx.proxy.responseHandlers {
		then = handler.Handle(ctx)
		//ctx.Logf("  ResponseHandler: %s [URL: %s]", then, ctx.Req.URL.Host)
		switch then {
		case DONE:
			return ctx.DispatchDoneHandlers()
		case NEXT:
			continue
		case FORWARD:
			//ctx.Logf("  *** UpdateAllowedCounter %s", ctx.Req.URL.Host)
			// Don't count streaming content in the allowed statistics
			if ctx.Resp != nil && ctx.Resp.StatusCode != 206 {
				ctx.proxy.UpdateAllowedCounter()
			}
			break
		case MITM:
			panic("MITM doesn't make sense when we are already parsing the request")
		case REJECT:
			rejected = true
			//ctx.Logf("  *** UpdateBlockedCounter %s", ctx.Req.URL.Host)
			ctx.proxy.UpdateBlockedCounter()
			ctx.proxy.UpdateBlockedHosts(ctx.Req.Host)
			//panic("REJECT a response ? then do what, send a 500 back ?")
		default:
			panic(fmt.Sprintf("Invalid value %v for Next after calling %v", then, handler))
		}
	}

	// A nil Resp means that the connection was dropped without even a status
	// code. This is typical if our DNS redirects to a closed port on this device.
	// In the case of a MITM attack, we can either drop the connection or
	// return a status 500 code.
	if ctx.Resp == nil || rejected {
		//err := fmt.Errorf("Response nil: %s", ctx.ResponseError)

		if rejected {
			//ctx.Logf("BLOCKED/ResponseFilter: %s", ctx.Req.URL)

			// Send back a 500 response for a blocked request
			//if ctx.IsSecure && ctx.IsThroughMITM {
				// The URL was previously allowed, so decrement the allowed counter
				//ctx.proxy.DecrementAllowedCounter()
				//ctx.proxy.UpdateBlockedCounter()
				//ctx.proxy.UpdateBlockedHosts(ctx.Req.Host)


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
					//ctx.Logf("  Serving 502")
					ctx.NewResponse(502, "text/plain; charset=utf-8", "502.2 Blocked by Winston [" + ext + "]")
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



			ctx.NewResponse(504, "text/plain; charset=utf-8", "504 Blocked by Winston / No response from server")
			return ctx.ForwardResponse(ctx.Resp)
		}

		//ctx.Logf("  Dispatching Done Handlers")
		ctx.DispatchDoneHandlers()
		return nil
	}

	return ctx.ForwardResponse(ctx.Resp)
}

func (ctx *ProxyCtx) DispatchDoneHandlers() error {
	var then Next
	for _, handler := range ctx.proxy.doneHandlers {
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
		default:
			// We're done
			return nil
		}
	}

	return nil
}

func (ctx *ProxyCtx) ForwardResponse(resp *http.Response) error {
	//ctx.Logf("  *** ForwardResponse ***")
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
	//nr, err :=

	// The response body must always be open at this point, so we close it.
	io.Copy(w, resp.Body)
	if err := resp.Body.Close(); err != nil {
		ctx.Warnf("Can't close response body %v", err)
	}
	//ctx.Logf("Copied %d bytes to client, error=%v", nr, err)

	ctx.DispatchDoneHandlers()

	return nil
}

// RLS: 8/14/2017 - Added support for Content Length instead of chunking. To use, set the ctx.NewBodyLength property.
func (ctx *ProxyCtx) forwardMITMResponse(resp *http.Response) error {

	// Make sure we close the original response body to prevent memory leaks. This has to be
	// done no matter what.
	defer resp.Body.Close();

	text := resp.Status
	//ctx.Logf("In forwardMITMResponse  Status: %s", text)
	statusCode := strconv.Itoa(resp.StatusCode) + " "
	if strings.HasPrefix(text, statusCode) {
		text = text[len(statusCode):]
	}
	// always use 1.1 to support chunked encoding
	if _, err := io.WriteString(ctx.Conn, "HTTP/1.1"+" "+statusCode+text+"\r\n"); err != nil {
		ctx.Warnf("Cannot write TLS response HTTP status from mitm'd client: %v", err)
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

		// Do we need to close the resp.Body here?
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
	ca := ctx.proxy.MITMCertConfig

	if ctx.MITMCertConfig != nil {
		ca = ctx.MITMCertConfig
	}

	//ctx.Logf("signing for %s", stripPort(host))
	err := ca.cert(host)
	if err != nil {
		ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
		return nil, err
	}

	// Hook the client Hello in order to generate fingerprint
	//ca.GetCertificate = ctx.getCertificateHook

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
/*func (ctx *ProxyCtx) copyAndClose(dst, src *net.TCPConn) {
	if _, err := io.Copy(dst, src); err != nil {
		ctx.Warnf("Error copying to client: %s", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}
*/

func (ctx *ProxyCtx) copyAndClose(w, r net.Conn, toClose chan net.Conn) {
	// TODO: Memory leak here - sometimes io.Copy never releases

	// This timeout is a sanity check simply designed to close connections after 5 minutes.
	timeoutDuration := 300 * time.Second
	r.SetReadDeadline(time.Now().Add(timeoutDuration))
	w.SetWriteDeadline(time.Now().Add(timeoutDuration))

	//start := time.Now()
	bytes, err := io.Copy(w, r)
	if err != nil && bytes <= 0 {
		ctx.Warnf("Error copying to client [%s]", ctx.Host(), err)
	}
	//end := time.Now()
	//duration := end.Sub(start) / time.Millisecond
	//ctx.Logf(1, "  *** copyAndClose duration %dms [%s]", duration, ctx.Host())
	toClose <- r
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

// Logf prints a message to the proxy's log. Should be used in a ProxyHttpServer's filter
// This message will be printed only if the Verbose field of the ProxyHttpServer is set to true
//
//	proxy.OnRequest().DoFunc(func(r *http.Request,ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
//		nr := atomic.AddInt32(&counter,1)
//		ctx.Printf("So far %d requests",nr)
//		return r, nil
//	})
func (ctx *ProxyCtx) Logf(level uint16, msg string, argv ...interface{}) {
	// RLS 2/10/2018 - Changed to bitmask so that we can toggle the different log levels.
	bitflag := uint16(1 << uint16((level - 1)))
	if ctx.proxy.Verbose && (level == 0 || ctx.proxy.VerbosityLevel&bitflag != 0) {
		ctx.printf(msg, argv...)
	}
}

// Warnf prints a message to the proxy's log. Should be used in a ProxyHttpServer's filter
// This message will always be printed.
//
//	proxy.OnRequest().DoFunc(func(r *http.Request,ctx *goproxy.ProxyCtx) (*http.Request, *http.Response){
//		f,err := os.OpenFile(cachedContent)
//		if err != nil {
//			ctx.Warnf("error open file %v: %v",cachedContent,err)
//			return r, nil
//		}
//		return r, nil
//	})
func (ctx *ProxyCtx) Warnf(msg string, argv ...interface{}) {
	ctx.Logf(6, "WARN: "+msg, argv...)
}

func (ctx *ProxyCtx) printf(msg string, argv ...interface{}) {
	ctx.proxy.Logger.Printf("[%03d] "+msg+"\n", append([]interface{}{ctx.Session & 0xFF}, argv...)...)
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
