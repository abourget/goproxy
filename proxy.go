// 6-29-2017 RLS - Added Tlsfailure method so callers can subscribe to TLS handshake failures
// 7011-2017 RLS - Added tproxy support to capture the original destination of https requests. This enables support for non-SNI clients.
package goproxy

import (
	"bufio"
	"bytes"
	"github.com/inconshreveable/go-vhost"
	"github.com/winstonprivacyinc/winston/goproxy/har"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	//"github.com/peterbourgon/diskv"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/winstonprivacyinc/go-conntrack"
	"strconv"
	"time"
	//"crypto/tls"
	"github.com/winstonprivacyinc/winston/shadownetwork"
	//"crypto/x509"
	//"github.com/valyala/fasthttp/fasthttputil"
	"io"
	"io/ioutil"
)

// The basic proxy type. Implements http.Handler.
type ProxyHttpServer struct {
	// session variable must be aligned in i386
	// see http://golang.org/src/pkg/sync/atomic/doc.go#L41
	sess int64
	// setting Verbose to true will log information on each request sent to the proxy
	Verbose bool

	// 0 (default) = Startup, service messages  and command output only
	// 1 Serious Errors
	// 2 HTTP/HTTPS blocked
	// 3 HTTP/HTTPS OK
	// 4 White/Blacklisting decisions
	// 5 Image files
	// 6 Warnings
	// 7 Partial content (status code 206) ?
	// 8 ElementHiding matches
	// 9 Allowed/Blocked Statistics logging
	VerbosityLevel uint16 //int

	// SniffSNI enables sniffing Server Name Indicator when doing CONNECT calls.  It will
	// thus answer to CONNECT calls with a "200 OK" even if the remote server might not
	// answer.  The result would be the shutdown of the connection instead of an appropriate
	// HTTP error code if the remote node doesn't answer.
	SniffSNI bool
	Logger   *log.Logger

	// Registered handlers
	connectHandlers  []Handler
	requestHandlers  []Handler
	responseHandlers []Handler
	doneHandlers     []Handler

	// NonProxyHandler will be used to handle direct connections to the proxy. You can
	// assign an `http.ServeMux` or some other routing libs here.  The default will return
	// a 500 error saying this is a proxy and has nothing to serve by itself.
	NonProxyHandler http.Handler

	// Logging and round-tripping
	harLog            *har.Har
	harLogEntryCh     chan harReqAndResp
	harFlushRequest   chan string
	harFlusherRunOnce sync.Once

	// Custom transport to be used
	Transport *http.Transport

	// Private transports
	//PrivateNetwork *shadowtransport.PrivateNetwork
	PrivateNetwork *shadownetwork.ShadowNetwork

	// Setting MITMCertConfig allows you to override the default CA cert/key used to sign MITM'd requests.
	MITMCertConfig *GoproxyConfigServer

	// ConnectDial will be used to create TCP connections for CONNECT requests
	// if nil, .Transport.Dial will be used
	ConnectDial func(network string, addr string) (net.Conn, error)

	// RLS 2/15/2018 - New context version of ConnectDial
	ConnectDialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

	// Callback function to determine if request should be traced.
	Trace func(ctx *ProxyCtx) traceRequest

	// Closure to alert listeners that a TLS handshake failed
	// RLS 6-29-2017
	Tlsfailure func(ctx *ProxyCtx, untrustedCertificate bool)

	// Closure to give listeners a chance to service a request directly. Return true if handled.
	HandleHTTP func(ctx *ProxyCtx) bool

	// If set to true, then the next HTTP request will flush all idle connections. Will be reset to false afterwards.
	FlushIdleConnections bool

	// RoundTripper which supports non-http protocols
	NonHTTPRoundTripper *NonHTTPRoundTripper

	UpdateAllowedCounter     func(string, string, string, int, int, int)
	UpdateBlockedCounter     func(string, string, string, int, bool)
	UpdateWhitelistedCounter func(string, string, string, int)

	// Defaults to a conntrak lookup but callers may substitute their own function (intended
	// primarily for unit testing). The connection must not be used or closed.
	DestinationResolver func(c net.Conn) string
}

// Performs sanity checking against a domain name. Is not intended to be a full blown
// domain name validator nor perform DNS lookup to confirm the host exists.
//
// TODO: Blink returns *.immedia-semi.com. Would be interesting to see if we could
// remove the leading invalid characters and use that as the host, but it is likely
// to be a brittle solution.
func checkDomain(host string) bool {
	if len(host) == 0 {
		return false
	}

	// For now, just check the first character. Some devices prefix with invalid characters.
	b := host[0]
	if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b >= 'A' && b <= 'Z') {
		return false
	}
	return true
}

// New proxy server, logs to StdErr by default
func NewProxyHttpServer() *ProxyHttpServer {
	proxy := ProxyHttpServer{
		Logger:           log.New(os.Stderr, "", log.LstdFlags),
		requestHandlers:  []Handler{},
		responseHandlers: []Handler{},
		connectHandlers:  []Handler{},
		NonProxyHandler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 500)
		}),

		// This transport is responsible for the outgoing connections to downstream websites.
		// FIX WINSTON 3-14 - Running out of open file descriptors. To avoid, set IdleConnTimeout.
		Transport: &http.Transport{
			//TLSClientConfig: tlsClientSkipVerify,
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 30 * time.Second,
			MaxIdleConns:          20,
			IdleConnTimeout:       60 * time.Second,

			//DialContext: (&net.Dialer{
			//	Timeout:   30 * time.Second,
			//	KeepAlive: 30 * time.Second,
			//	DualStack: true,
			//}).DialContext,
		},
		//MITMCertConfig:  GoproxyCaConfig,
		harLog:              har.New(),
		harLogEntryCh:       make(chan harReqAndResp, 10),
		harFlushRequest:     make(chan string, 10),
		NonHTTPRoundTripper: &NonHTTPRoundTripper{
			//TLSClientConfig: tlsClientSkipVerify,
		},
	}

	// RLS 3/18/2018 - Add session ticket support
	// Setting a relatively low number will force tickets out more quickly, helping to prevent against snooping attacks.
	//proxy.Transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(25)

	// RLS 7/30/2018 - Adds support for non-http protocols
	proxy.Transport.RegisterProtocol("nonhttp", proxy.NonHTTPRoundTripper)
	proxy.Transport.RegisterProtocol("nonhttps", proxy.NonHTTPRoundTripper)
	//proxy.NonHTTPRoundTripper.DialContext = proxy.Transport.DialContext

	// RLS 2/15/2018
	// This looks for a proxy on the network and sets up a dialer to call it.
	// We don't use this but it's left in case we ever need to daisy chain proxies.
	proxy.ConnectDial = dialerFromEnv(&proxy)
	proxy.ConnectDialContext = dialerFromEnvContext(&proxy)

	proxy.DestinationResolver = resolveconntrackdestination

	return &proxy
}

// Call after the private network has been initialized to have proxy automatically redirect requests through it.
// The proxy will simply forward requests through the local network until this is called.
func (proxy *ProxyHttpServer) SetShadowNetwork(sn *shadownetwork.ShadowNetwork) {
	if sn == nil {
		return
	}

	sn.DefaultTransport = proxy.Transport
	proxy.PrivateNetwork = sn
}

// Calls to the signature reporting service (https://winstonprivacysignature.conf) will save the signature
// here so it can be retrieved by a follow up http request if necessary. This is shared across all proxies.
var lastSignature = ""

func (proxy *ProxyHttpServer) LastSignature() string {
	return lastSignature
}
func (proxy *ProxyHttpServer) SetSignature(signature string) {
	lastSignature = signature
}

// Experimental version of ListenAndServe which allows us to handle our own request processing.
// Should only be used for unencrypted (port 80) requests.
func (proxy *ProxyHttpServer) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)

	if err != nil {
		log.Fatalf("Error listening for HTTP connections (err 1) - %v", err)
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting new HTTP connection (err 2) - %v", err)
			panic("Stopping for analysis...")
			continue
		}

		go func(c net.Conn) {
			//log.Printf("[INFO] Incoming HTTP request - source: %s / destination: %s", c.RemoteAddr().String(), c.LocalAddr().String())

			// If true, a connection will be opened to the destination and left open
			// until server, client closes (or timeout) Because this is HTTP, we
			// still have the ability to inspect or modify headers but that is up to
			// the handler.

			//isnonhttpprotocol := false

			var buf bytes.Buffer
			tee := io.TeeReader(c, &buf)
			connteereader := bufio.NewReader(tee)

			var req *http.Request
			req, err = http.ReadRequest(connteereader)

			if err != nil {
				// TODO: Try to recover as much information from the original request
				// as possible so that we can act on headers that might actually be
				// there (especially referrer and user agent)
				//fmt.Printf("[DEBUG] ServeHTTP() - Couldn't parse request: %s\nOriginal Request:\n%s\n", err.Error(), string(buf.Bytes()))

				req = &http.Request{
					Method: "",
					//URL:	&url.URL{
					//Host: net.JoinHostPort(Host, "80"),
					//},
					Proto:      "http", // assume http, but it's probably not.
					ProtoMajor: 0,
					ProtoMinor: 0,
					Header:     make(http.Header),
					Body:       nil,
					Host:       "",
					//RequestURI: Host,
				}
				//isnonhttpprotocol = true

			}

			// To print any local responses (errors) to stdout, uncomment SpyConnection.
			// This will not print out anything related to forwarded connections.
			// resp := notsodumbResponseWriter{Conn: &SpyConnection{c}, ResponseHeader: &req.Header}

			resp := notsodumbResponseWriter{Conn: c, ResponseHeader: &req.Header}

			// Failover Host detection - if we couldn't read the host from the HTTP headers, check the
			// conntrack table to get the original destination.
			//fmt.Printf("[DEBUG] ServeHTTP() - req: %+v\n", req.Host)
			if !checkDomain(req.Host) {
				destination := proxy.DestinationResolver(c)
				//fmt.Println("[DEBUG] Invalid HTTP host specified. Determining original destination through conntrak:", req.Host, "->", destination)
				req.Host = destination
			}

			// If still invalid, we couldn't resolve it. Drop the request.
			if !checkDomain(req.Host) {
				fmt.Printf("[ERROR] Failed to determine original destination: %s. Dropping request.\n", req.Host)
				c.Close()
				return
			}

			// Empty buffer / no request - drop it.
			if buf.Len() == 0 {
				//fmt.Printf("[ERROR] Received zero length request to host: %s. Dropping request.\n", req.Host)
				c.Close()
				return
			}

			proxy.HandleHTTPConnection(c, req, &resp, &buf)
		}(c)
	}
}

// Expects a parsed request object, connection and a response writer. Will forward the connection to the original
// destination (found in r.Host). If CONNECT, it will simply open a connection and the client must
// negotiate it. Otherwise, it will replay the original request to the upstream server and pipe
// the response back without modification. This is a major design change from the original implementation
// which parsed (and potentially modified) the response. We no longer do this within the proxy.
//
// The response writer is needed in case we need to return our own response (ie: an error message) back to the caller.
//
// Important: Handlers will only be called once on the initial connection to a particular host. Because we
// are tunneling HTTP requests, subsequent requests will not be visible to us unless a new TCP connection is
// established. This is mitigated in practice because devices with the browser extension installed handle their
// own logging.
func (proxy *ProxyHttpServer) HandleHTTPConnection(c net.Conn, r *http.Request, w http.ResponseWriter, originalrequest *bytes.Buffer) {
	ctx := &ProxyCtx{
		Method:         r.Method,
		SourceIP:       r.RemoteAddr, // pick it from somewhere else ? have a plugin to override this ?
		Req:            r,
		ResponseWriter: w,
		UserData:       make(map[string]string),
		UserObjects:    make(map[string]interface{}),
		Session:        atomic.AddInt64(&proxy.sess, 1),
		Proxy:          proxy,
		MITMCertConfig: proxy.MITMCertConfig,
		Tlsfailure:     proxy.Tlsfailure,
		VerbosityLevel: proxy.VerbosityLevel,
		DeviceType:     -1,
		RequestTime:    time.Now(),
		TunnelRequest:  true, // Forces request through verbatim.
		Conn:           c,
	}

	if originalrequest != nil {
		ctx.NonHTTPRequest = originalrequest.Bytes()
	}

	// Set up host and port
	ctx.host = r.Host
	if ctx.host == "" {
		// Fail safe. Should we ever get here?
		ctx.host = r.URL.Host
		fmt.Println("[WARN] Did not have a host in HandleHTTPConnection(). Failed over to r.URL.Host", ctx.host)
	}

	// For any non-CONNECT request, we must guarantee the following before calling the handlers.
	// ctx.host is set to the actual host of the request (ie: www.example.com)
	// r.URL.Host is set to domain+port (ie: www.example.com:80)
	// r.URL.Scheme is set to http
	// TODO: This could be cleaner. It's messy because we've tacked on a lot of code at different times.
	if r != nil && r.URL != nil && r.Method != "CONNECT" && !r.URL.IsAbs() {
		//fmt.Println("[DEBUG] HandleHTTPConnection() - converting relative URL to absolute. r.URL:", r.URL, "r.URL.Host", r.URL.Host)
		r.URL.Scheme = "http"
		r.URL.Host = net.JoinHostPort(ctx.host, "80")
		//fmt.Printf("[DEBUG] HandleHTTPConnection() - r.URL now: %+v\n", r.URL)
	}

	// Set up request trace
	if proxy.Trace != nil {
		ctx.Trace = proxy.Trace(ctx)
		if ctx.Trace.Modified {
			setupTrace(ctx, "Modified request")

			// Copy the request body
			buf, _ := ioutil.ReadAll(r.Body)
			ctx.TraceInfo.ReqBody = &buf
			rdr2 := ioutil.NopCloser(bytes.NewBuffer(*ctx.TraceInfo.ReqBody))
			r.Body.Close()
			r.Body = rdr2
		}
	}

	//fmt.Println("[DEBUG] HandleHTTPConnection() - ctx.host", r.Method, "Scheme:", r.URL.Scheme, "Host:", r.Host, "URL Host", r.URL.Host, "URI:", r.RequestURI)

	// If no port was provided, guess it based on the scheme.
	if strings.IndexRune(ctx.host, ':') == -1 {
		if r.URL == nil || r.URL.Scheme == "http" || r.URL.Scheme == "ws" {
			ctx.host += ":80"
		} else if r.URL.Scheme == "https" || r.URL.Scheme == "wss" {
			ctx.host += ":443"
		}
	}

	// Check for websockets request. Forward without intercepting the response.
	if ctx.Req.Header.Get("Upgrade") != "" {
		//fmt.Printf("[DEBUG] Proxy.go::Websocket connection detected. %+v\n", ctx.Req)
		ctx.TunnelRequest = true
		//ctx.Req.URL.Scheme = "ws"
	}

	// RLS 2/19/2019 - Anything which is not a CONNECT request will go to DispatchRequestHandlers.
	// This will now forward the original request without modifying it.
	if r.Method == "CONNECT" {
		//if strings.Contains(ctx.host, "websocket") {
		//	fmt.Println("[DEBUG] HandleHTTPConnection() -> dispatchConnectHandlers host", ctx.host, " Method:", r.Method)
		//}
		proxy.dispatchConnectHandlers(ctx)
	} else {
		// Important: NonHttpProtocols (websockets) that are initiated over port 80 must route through
		// the Request handlers. If routed through the Connect Handlers, the original request will
		// route to ForwardConnect() and be dropped.
		// Give listener a chance to service the request
		if proxy.HandleHTTP != nil {
			if proxy.HandleHTTP(ctx) {
				return
			}
		}
		//fmt.Printf("[DEBUG] ServeHTTP() -> dispatchRequestHandlers - original request:\n%s\n", ctx.NonHTTPRequest)

		//fmt.Println("[DEBUG] ServeHTTP() -> dispatchRequestHandlers host", ctx.host, "Method:", r.Method, "  ctx.IsNonHttpProtocol: ", ctx.IsNonHttpProtocol)
		proxy.DispatchRequestHandlers(ctx)
	}

	// Complete request trace
	if ctx.Trace.Modified {
		writeTrace(ctx)
	}

	// Duplicate the request but skip the request and response handling
	// Removed - we are not modifying the request any longer.
	/*if ctx.Trace.Unmodified {
		// TODO: Refactor this. Consider using a channel instead of sleeping.
		time.Sleep(10 * time.Second)
		// Duplicate the request and send it through as whitelisted. This will show us the original
		// information without any modification.
		ctxOrig := &ProxyCtx{
			Method:         r.Method,
			SourceIP:       r.RemoteAddr, // pick it from somewhere else ? have a plugin to override this ?
			Req:            r,
			ResponseWriter: w,
			UserData:       make(map[string]string),
			UserObjects:    make(map[string]interface{}),
			Session:        atomic.AddInt64(&proxy.sess, 1),
			Proxy:          proxy,
			MITMCertConfig: proxy.MITMCertConfig,
			Tlsfailure:	proxy.Tlsfailure,
			VerbosityLevel: proxy.VerbosityLevel,
			DeviceType: -1,
			Trace:			ctx.Trace,
			SkipRequestHandler: 	true,
			SkipResponseHandler: 	true,
			RequestTime:	time.Now(),

		}

		r.URL.Scheme = "http"
		r.URL.Host = r.Host //net.JoinHostPort(r.Host, "80")

		setupTrace(ctxOrig, "Unmodified Request")

		// Copy the original request body
		// TODO: Close the original request body so we don't leak a connection
		// 			ctx.TraceInfo.ReqBody = []byte("custname=Winston123&custtel=3122820162&custemail=richardlstokes2%40gmail.com&delivery=&comments=")

		//fmt.Printf("[DEBUG] Unmodified request - copying original request body (%d): \n%s\n", len(ctx.TraceInfo.ReqBody), string(ctx.TraceInfo.ReqBody))
		rdr2 := ioutil.NopCloser(bytes.NewBuffer(*ctx.TraceInfo.ReqBody))
		r.Body.Close()
		r.Body = rdr2
		r.ContentLength = int64(len(*ctx.TraceInfo.ReqBody))

		proxy.DispatchRequestHandlers(ctxOrig)

		writeTrace(ctxOrig)

	}
	*/
}

// formatRequest generates ascii representation of a request. Useful when debugging.
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

// Given a connection, resolves its original destination by looking it up in the conntrak tables.
// This is required for non-TLS protocols or for connections initiated by devices which do not
// send a valid SNI field in the CLIENTHELLO message.
func resolveconntrackdestination(c net.Conn) string {
	connections, connerr := conntrack.Flows()
	if connerr != nil {
		log.Printf("[ERROR] non-SNI client detected but couldn't read connection table. Dropping connection request. [%v]\n", connerr)
		return ""
	}

	var nonSNIHost net.IP

	// Get the source port
	sourcePort := 0
	portIndex := strings.IndexRune(c.RemoteAddr().String(), ':')

	if portIndex == -1 {
		log.Println("[ERROR] non-SNI client detected but there was no source port on the request. Dropping connection request.")
		return ""
	} else {
		sourcePort, _ = strconv.Atoi(c.RemoteAddr().String()[(portIndex + 1):])
	}

	if sourcePort == 0 {
		log.Println("[ERROR] non-SNI client detected but couldn't parse source port on the request. Dropping connection request.")
		return ""
	}

	for _, flow := range connections {
		if flow.Original.SPort == sourcePort {
			nonSNIHost = flow.Original.Destination
		}
	}

	return nonSNIHost.String()
}

// This function listens for TLS requests on the specified port.
// It should be called within a goroutine, otherwise it will block forever.
func (proxy *ProxyHttpServer) ListenAndServeTLS(httpsAddr string) error {
	ln, err := net.Listen("tcp", httpsAddr)

	if err != nil {
		log.Fatalf("Error listening for https connections (err 1) - %v", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting new connection (err 2) - %v", err)
			panic("Stopping for analysis...")
			continue
		}
		go func(c net.Conn) {
			//log.Printf("[INFO] INCOMING TLS CONNECTION - source: %s / destination: %s", c.RemoteAddr().String(), c.LocalAddr().String())
			tlsConn, err := vhost.TLS(c)

			forwardwithoutintercept := false
			if err != nil {
				// Honeywell Lynx 5100 (and possibly other devices) send a non-TLS protocol over port 443.
				//log.Println("[WARN] Non-TLS protocol detected on port 443.")
				forwardwithoutintercept = true
			}

			var Host = tlsConn.Host()

			//fmt.Println("[DEBUG] ListenAndServeTLS() - ClientHELLO server name/host:", tlsConn.Host())
			if !checkDomain(Host) {
				// Non-SNI request handling routine
				//log.Printf("[DEBUG] Invalid host or non-SNI client detected - host: %s\n", tlsConn.Host())
				Host = proxy.DestinationResolver(c)
			}

			// If still invalid, we couldn't resolve it. Drop the request.
			if !checkDomain(Host) {
				fmt.Printf("[ERROR] Failed to parse original HTTP host: %s. Dropping request.\n", Host)
				tlsConn.Close()
				return
			}

			// Check for local host
			// TODO: Determine Winston IP address dynamically. For now, we reserve 192.168.102.* for ourselves.
			if strings.HasPrefix(Host, "192.168.102.") {
				//log.Printf("[DEBUG] non-SNI attempt at local host. Dropping request: [%s]  non-SNI Host: [%s]\n", Host, nonSNIHost)
				tlsConn.Close()
				return
			}

			// If we weren't provided with a port, assume 443
			var hostwithport = Host
			if strings.IndexRune(Host, ':') == -1 {
				hostwithport += ":443"
			}

			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: Host,
					Host:   hostwithport,
				},
				Host:   Host,
				Header: make(http.Header),
			}
			resp := dumbResponseWriter{tlsConn}

			// Set up a context object for the current request
			ctx := &ProxyCtx{
				Method:         connectReq.Method,
				SourceIP:       connectReq.RemoteAddr, // pick it from somewhere else ? have a plugin to override this ?
				Req:            connectReq,
				ResponseWriter: resp,
				UserData:       make(map[string]string),
				UserObjects:    make(map[string]interface{}),
				Session:        atomic.AddInt64(&proxy.sess, 1),
				Proxy:          proxy,
				MITMCertConfig: proxy.MITMCertConfig,
				Tlsfailure:     proxy.Tlsfailure,
				VerbosityLevel: proxy.VerbosityLevel,
				DeviceType:     -1,
				RequestTime:    time.Now(),
				TunnelRequest:  forwardwithoutintercept,
				IsSecure:       true,
			}

			ctx.host = hostwithport

			//fmt.Println("[DEBUG] ListenAndServeTLS() - ctx.Host:", ctx.host)

			// We've sniffed the SNI record already through the vlshost muxer.
			// This just sets the flags to avoid throwing warnings.
			ctx.sniffedTLS = true
			ctx.sniHost = Host

			// TODO: Should caller handle this or should we?
			// Create a signature string for the accepted ciphers
			if tlsConn.ClientHelloMsg != nil && len(tlsConn.ClientHelloMsg.CipherSuites) > 0 {
				// RLS 10/10/2017 - Expanded signature
				// Generate a fingerprint for the client. This enables us to whitelist
				// failed TLS queries on a per-client basis.
				ctx.CipherSignature = GenerateSignature(tlsConn.ClientHelloMsg, false)
			} else {
				ctx.CipherSignature = ""
			}

			// TEST
			// Set up a shared buffer so the second request can see the original request body
			//var buf []byte
			if proxy.Trace != nil {
				ctx.Trace = proxy.Trace(ctx)
				if ctx.Trace.Modified {

					//fmt.Printf("ClientHELLO: \n %+v\n", tlsConn.ClientHelloMsg)

					setupTrace(ctx, "Modified Request")
					//fmt.Printf("[DEBUG] Original request location: [%p]\n", ctx.TraceInfo.ReqBody)
					//ctx.TraceInfo.ReqBody = &buf
				}
			}

			// Print out TLS CLIENTHELLO message. Useful for inspecting cipher suites.
			//if ctx.Trace {
			//	fmt.Printf("[TRACE] CLIENTHELLO [%s] [Vers=%v] =\n%+v\n\n", ctx.CipherSignature, (*tlsConn.ClientHelloMsg).Vers, *tlsConn.ClientHelloMsg)
			//}

			fmt.Println("[DEBUG] ListenAndServeTLS() - request host:", ctx.host, ctx.IsSecure)

			proxy.dispatchConnectHandlers(ctx)

			// If tracing, run the same request but skip any filtering.
			/*if ctx.Trace.Unmodified {

				// Wait a little while for the original request to complete
				// TODO: Use a channel for this. Also send back original request body???
				time.Sleep(10 * time.Second)

				//fmt.Printf("[DEBUG] original http.Request 1 - [%p] (%d)\n%s\n", ctx.TraceInfo.ReqBody, len(*ctx.TraceInfo.ReqBody), string(*ctx.TraceInfo.ReqBody))

				//fmt.Printf("[TRACE] Running parallel https request to %s\n", ctx.Req.URL)
				// Create a bidirectional, in-memory connection with fake client. This enables us to spoof
				// the original client and utilize the same logic that the first request did.
				var pipe *fasthttputil.PipeConns
				pipe = fasthttputil.NewPipeConns()

				// Create a mock client
				fakeclient := http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
						DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
							return pipe.Conn1(), nil
						},
					},
				}

				// Make the request
				Url := ctx.Req.URL.String()
				go func() {
					request, err := http.NewRequest(connectReq.Method, Url, nil)

					//fmt.Printf("[DEBUG] proxy.go request: %+v\n\n", request)

					for k, v := range ctx.TraceInfo.originalheaders {
						//fmt.Printf("Copy header: %s : %s\n", k, v)
						request.Header.Set(k, v)
					}

					fakeresp, err := fakeclient.Do(request)
					if err != nil {
						fmt.Printf("[TRACE] Fake client didn't receive a response. err=%+v\n", err)
						return
					}

					defer fakeresp.Body.Close()

					body, err := ioutil.ReadAll(fakeresp.Body)
					if err != nil {
						fmt.Printf("[TRACE] Error while reading body. %+v\n", err)
						return
					}
					// Process the response and close. We wait one second so the response body
					// occurs after the headers.
					time.Sleep(time.Second)
					fmt.Printf("[TRACE] Unmodified Response Body [%d bytes]: %+v\n", len(body), string(body))


				}()

				// Handshakes with our fake client. The connection should already be open.
				tlsConnClient, err := vhost.TLS(pipe.Conn2())
				if err != nil {
					fmt.Printf("[TRACE] Error - server couldn't open pipe to fake client. Unmodified https response not available. $+v\n", err)
				} else {
					connectReqCopy := &http.Request{
						Method: "CONNECT",
						URL: connectReq.URL,
						Host:   Host,
						Header: make(http.Header),
					}
					respClient := dumbResponseWriter{tlsConnClient}

					// Duplicate the request and send it through as whitelisted. This will show us the original
					// information without any modification.
					ctxOrig := &ProxyCtx{
						Method:         connectReqCopy.Method,
						SourceIP:       connectReqCopy.RemoteAddr, // pick it from somewhere else ? have a plugin to override this ?
						Req:            connectReqCopy,
						ResponseWriter: respClient,
						UserData:       make(map[string]string),
						UserObjects:    make(map[string]interface{}),
						Session:        atomic.AddInt64(&proxy.sess, 1),
						Proxy:          proxy,
						MITMCertConfig: proxy.MITMCertConfig,
						Tlsfailure:        proxy.Tlsfailure,
						VerbosityLevel: proxy.VerbosityLevel,
						DeviceType: -1,
						CipherSignature:        ctx.CipherSignature,
						sniffedTLS:             ctx.sniffedTLS,
						sniHost:                ctx.sniHost,
						host:			ctx.host,
						Trace:                  ctx.Trace,
						SkipRequestHandler:     true,
						SkipResponseHandler:    true,
					}

					setupTrace(ctxOrig, "Unmodified Request")

					// Copy the body and method from the original request to the one
					ctxOrig.TraceInfo.ReqBody = ctx.TraceInfo.ReqBody
					ctxOrig.TraceInfo.Method = ctx.TraceInfo.Method

					//fmt.Printf("[DEBUG] request body after tracesetup: [%p] %s\n", ctxOrig.TraceInfo.ReqBody, string(*ctxOrig.TraceInfo.ReqBody))

					//fmt.Printf("[TRACE] Dispatching connect handlers to %+v\n", ctxOrig.Req.URL)
					proxy.dispatchConnectHandlers(ctxOrig)


				}
			}*/

		}(c)
	}
}

func GenerateSignature(h *vhost.ClientHelloMsg, debug bool) string {

	// Create string for cipher suites
	// These have to be sorted because the same client can return them in an arbitrary order
	var b bytes.Buffer
	var logbuf bytes.Buffer

	// Google clients based on BoringSSL will return semi-random cipher suites. These should be ignored
	// but we can use their presence as an additional bit of entropy.
	// Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-01#section-5
	for _, suite := range h.CipherSuites {
		switch suite {
		case 2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250:
		default:
			b.Write([]byte(strconv.Itoa(int(suite))))
		}

	}
	b.Write([]byte("-"))

	// Create string for curves. The first value is often different for the same client, so we ignore it.
	for _, curve := range h.SupportedCurves {
		switch curve {
		case 2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354, 35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250:
		default:
			b.Write([]byte(strconv.Itoa(int(curve))))
		}

	}
	b.Write([]byte("-"))

	if debug {
		logbuf.Write([]byte("-"))
	}

	for _, point := range h.SupportedPoints {
		b.Write([]byte(strconv.Itoa(int(point))))
	}
	b.Write([]byte("-"))

	for _, comp := range h.CompressionMethods {
		b.Write([]byte(strconv.Itoa(int(comp))))
	}
	b.Write([]byte("-"))

	OcspStapling := "S0"
	if h.OcspStapling {
		OcspStapling = "S1"
	}

	ticketssupported := "T0"
	if h.TicketSupported {
		ticketssupported = "T1"
	}
	nextprotoneg := "N0"
	if h.NextProtoNeg {
		nextprotoneg = "N1"
	}

	// Concatenate the unique identifying informatoin from the TLS handshake
	signature := strconv.FormatUint(uint64(h.Vers), 10) + "-" + string(b.Bytes()) + "-" + OcspStapling + "-" + ticketssupported + "-" + nextprotoneg

	// Note: this has to be compressed to avoid errors associated with too long filenames.
	hasher := md5.New()
	hasher.Write([]byte(signature))
	encodedsignature := hex.EncodeToString(hasher.Sum(nil))

	//if debug {
	//	log.Printf("  *** detected target client: [%s] - [%s]\n", encodedsignature, signature)
	//}

	return encodedsignature
}

// SetMITMCertConfig sets the CA Config to be used to sign man-in-the-middle'd
// certificates. You can load some []byte with `LoadCAConfig()`. This bundle
// gets passed into the `ProxyCtx` and may be overridden in the [TODO:
// FIXME] `HandleConnect()` callback, before doing SNI sniffing.
func (proxy *ProxyHttpServer) SetMITMCertConfig(config *GoproxyConfigServer) {
	proxy.MITMCertConfig = config
}

// copied/converted from https.go
type dumbResponseWriter struct {
	net.Conn
	//header http.Header
}

func (dumb dumbResponseWriter) Header() http.Header {
	// Caller needs to check for nil... otherwise will panic here!
	//return nil
	//dumb.header
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		// throw away the HTTP OK response from the faux CONNECT request
		return len(buf), nil
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {

	// For now, anything we write to a dumbresponsewriter is going into a black hole...
	// Not sure what this should actally be doing...
	//log.Println("WARN: WriteHeader called on hijacked connection. status: %d %v", code, dumb.header)

	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
