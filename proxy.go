// 6-29-2017 RLS - Added Tlsfailure method so callers can subscribe to TLS handshake failures
// 7011-2017 RLS - Added tproxy support to capture the original destination of https requests. This enables support for non-SNI clients.
package goproxy

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"github.com/inconshreveable/go-vhost"
	"github.com/abourget/goproxy/har"
	"net/url"
	"github.com/peterbourgon/diskv"
	"time"
	"fmt"
	"encoding/binary"
	"github.com/honnef.co/go-conntrack"
	"strconv"
	"encoding/hex"
	"crypto/md5"
	"context"
	"crypto/tls"
	"github.com/winston/shadownetwork"
	//"crypto/x509"
	"github.com/valyala/fasthttp/fasthttputil"
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
	MITMCertConfig *GoproxyConfig

	// ConnectDial will be used to create TCP connections for CONNECT requests
	// if nil, .Transport.Dial will be used
	ConnectDial func(network string, addr string) (net.Conn, error)

	// RLS 2/15/2018 - New context version of ConnectDial
	ConnectDialContext func(ctx context.Context, network string, addr string) (net.Conn, error)

	// Callback function to determine if request should be traced.
	Trace func(ctx *ProxyCtx) (bool)

	// Closure to alert listeners that a TLS handshake failed
	// RLS 6-29-2017
	Tlsfailure func(ctx *ProxyCtx, untrustedCertificate bool)

	// Closure to give listeners a chance to service a request directly. Return true if handled.
	HandleHTTP func(ctx *ProxyCtx) (bool)

	// References to persistent caches for statistics collection
	// RLS 7-5-2017
	blockedmu sync.Mutex
	BlockedStats *diskv.Diskv

	allowedmu sync.Mutex
	AllowedStats *diskv.Diskv

	blockedhostsmu sync.Mutex
	BlockedHosts *diskv.Diskv

	//failuremu sync.Mutex
	//FailedStats *diskv.Diskv

	// If set to true, then the next HTTP request will flush all idle connections. Will be reset to false afterwards.
	FlushIdleConnections bool

	// Calls to the signature reporting service (https://winstonprivacysignature.conf) will save the signature
	// here so it can be retrieved by a follow up http request if necessary.
	LastSignature string

	// RoundTripper which supports non-http protocols
	NonHTTPRoundTripper *NonHTTPRoundTripper

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
		Transport: &http.Transport{
			TLSClientConfig: tlsClientSkipVerify,	// Ignore this poorly chosen name. This is a TLS config (see certs.go)
			Proxy:           http.ProxyFromEnvironment,
			TLSHandshakeTimeout: time.Second * time.Duration(10),	// TLS handshake timeout
		},
		MITMCertConfig:  GoproxyCaConfig,
		harLog:          har.New(),
		harLogEntryCh:   make(chan harReqAndResp, 10),
		harFlushRequest: make(chan string, 10),
		NonHTTPRoundTripper: &NonHTTPRoundTripper{
			TLSClientConfig: tlsClientSkipVerify,
		},
	}



	// RLS 3/18/2018 - Add session ticket support
	// Setting a relatively low number will force tickets out more quickly, helping to prevent against snooping attacks.
	proxy.Transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(25)

	// RLS 7/30/2018 - Adds support for non-http protocols
	proxy.Transport.RegisterProtocol("nonhttp", proxy.NonHTTPRoundTripper)
	proxy.Transport.RegisterProtocol("nonhttps", proxy.NonHTTPRoundTripper)
	//proxy.NonHTTPRoundTripper.DialContext = proxy.Transport.DialContext

	// RLS 2/15/2018
	// This looks for a proxy on the network and sets up a dialer to call it.
	// We don't use this but it's left in case we ever need to daisy chain proxies.
	proxy.ConnectDial = dialerFromEnv(&proxy)
	proxy.ConnectDialContext = dialerFromEnvContext(&proxy)

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


func (proxy *ProxyHttpServer) LazyWrite(PersistSeconds int) {
	// RLS 7/7/2017
	// Set up a thread to occasionally persist the stats caches to disk
	if PersistSeconds > 0 {
		ticker := time.NewTicker(time.Second * time.Duration(PersistSeconds))
		go func() {
			for {
				select {
				case <-ticker.C:
					//fmt.Println(" *** PERSISTING CACHES *** ")
					if proxy.AllowedStats != nil {
						proxy.AllowedStats.Persist()
					}
					if proxy.BlockedStats != nil {
						proxy.BlockedStats.Persist()
					}
					if proxy.BlockedHosts != nil {
						proxy.BlockedHosts.Persist()
					}
				}

			}
		}()
	}
}
// Standard net/http function. Shouldn't be used directly, http.Serve will use it.
func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//r.Header["X-Forwarded-For"] = w.RemoteAddr()	

	//fmt.Println("ServeHTTP()")

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
		Tlsfailure:	proxy.Tlsfailure,
		UpdateAllowedCounter:	proxy.UpdateAllowedCounter,
		UpdateBlockedCounter:	proxy.UpdateBlockedCounter,
		UpdateBlockedCounterByN:	proxy.UpdateBlockedCounterByN,
		UpdateBlockedHostsByN:	proxy.UpdateBlockedHostsByN,
		VerbosityLevel: proxy.VerbosityLevel,
		DeviceType: -1,
		Trace:		false,
	}


	ctx.host = r.URL.Host
	if strings.IndexRune(ctx.host, ':') == -1 {
		if r.URL.Scheme == "http" {
			ctx.host += ":80"
		} else if r.URL.Scheme == "https" {
			ctx.host += ":443"
		}
	}

	// Set up request trace
	if proxy.Trace != nil {
		shouldTrace := proxy.Trace(ctx)
		if shouldTrace {
			setupTrace(ctx, "Unmodified request")
		}
	}

	if r.Method == "CONNECT" {
		proxy.dispatchConnectHandlers(ctx)
	} else {
		if ctx.Trace {
			fmt.Printf("[DEBUG] ServeHTTP() - Host: %s  IsAbs: %t\n", r.Host, r.URL.IsAbs())
		}

		if !r.URL.IsAbs() {
			if ctx.Trace {
				fmt.Printf("[DEBUG] ServeHTTP() - Host: %s\n", r.Host)
			}

			r.URL.Scheme = "http"
			r.URL.Host = r.Host //net.JoinHostPort(r.Host, "80")

			// Give listener a chance to service the request
			if proxy.HandleHTTP != nil {
				if proxy.HandleHTTP(ctx) {
					return
				}
			//if r.Host == "winston.conf" {
			//	// TODO: Callback to Winston handler here
			//	proxy.NonProxyHandler.ServeHTTP(w, r)
			//	if ctx.Trace {
			//		// Complete request trace
			//		writeTrace(ctx)
			//	}
			//	return
			}


		}

		proxy.DispatchRequestHandlers(ctx)
	}

	// Complete request trace
	if ctx.Trace {
		writeTrace(ctx)

	}

	// Duplicate the request but skip the request and response handling
	if ctx.Trace {
		// TODO: Use channel instead of sleeping
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
			UpdateAllowedCounter:	proxy.UpdateAllowedCounter,
			UpdateBlockedCounter:	proxy.UpdateBlockedCounter,
			UpdateBlockedCounterByN:	proxy.UpdateBlockedCounterByN,
			UpdateBlockedHostsByN:	proxy.UpdateBlockedHostsByN,
			VerbosityLevel: proxy.VerbosityLevel,
			DeviceType: -1,
			Trace:			true,
			SkipRequestHandler: 	true,
			SkipResponseHandler: 	true,
		}

		r.URL.Scheme = "http"
		r.URL.Host = r.Host //net.JoinHostPort(r.Host, "80")

		setupTrace(ctxOrig, "Unmodified Request")
		proxy.DispatchRequestHandlers(ctxOrig)

		writeTrace(ctxOrig)

	}

}


// ListenAndServe launches all the servers required and listens. Use this method
// if you want to start listeners for transparent proxying.
func (proxy *ProxyHttpServer) ListenAndServe(addr string) error {
	//fmt.Printf("*** ListenAndServe() called\n")
	return http.ListenAndServe(addr, proxy)
}

// This function listens for TCP requests on the specified port.
// It should be called within a goroutine, otherwise it will block forever.

func (proxy *ProxyHttpServer) ListenAndServeTLS(httpsAddr string) error {
	ln, err := net.Listen("tcp", httpsAddr)
	//log.Printf("*** ListenAndServeTLS called... %s\n", httpsAddr)

	// Alternate socket based listener which can receive requests from packets marked with
	// IP addresses not belonging to this server. Slow but may be useful.
	//ln, err := tproxy.TcpListen(httpsAddr)

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
			//log.Printf(" *** INCOMING TLS CONNECTION - source: %s / destination: %s", c.RemoteAddr().String(), c.LocalAddr().String())
			tlsConn, err := vhost.TLS(c)

			if err != nil {
				log.Printf("Error accepting new connection (err 3) - %v", err)
				//log.Printf(" *** BAD TLS CONNECTION? - source: %s / destination: %s", c.RemoteAddr().String(), c.LocalAddr().String())
			}


			// Non-SNI request handling routine
			var nonSNIHost net.IP
			if tlsConn.Host() == "" {
				//log.Printf("   *** non-SNI client detected - source: %s / destination: %s", c.RemoteAddr().String(), c.LocalAddr().String())

				// Some devices (Smarthome devices and especially anything by Amazon) do not
				// send the hostname in the SNI extension. To get around this, we will query
				// the Linux ip_conntrack tables to get the original IP address. Any non-local
				// addresses will be tunnelled through to their original destination.
				connections, connerr := conntrack.Flows()
				if connerr != nil {
					log.Println("non-SNI client detected but couldn't read connection table. Dropping connection request. [%v]", connerr)
					return
				}

				// Get the source port
				sourcePort := 0
				portIndex := strings.IndexRune(c.RemoteAddr().String(), ':')

				if portIndex == -1 {
					log.Println("non-SNI client detected but there was no source port on the request. Dropping connection request.")
					return
				} else {
					sourcePort, _ = strconv.Atoi(c.RemoteAddr().String()[(portIndex+1):])
				}

				if sourcePort == 0 {
					log.Println("non-SNI client detected but couldn't parse source port on the request. Dropping connection request.")
					return
				}

				for _, flow := range connections {
					if flow.Original.SPort == sourcePort {
						nonSNIHost = flow.Original.Destination
					}
				}

			}

			var Host = tlsConn.Host()
			if Host == "" {
				Host = nonSNIHost.String()
				//log.Printf("[DEBUG]  Non-SNI request detected - destination: [%s]\n", Host)
			}

			// Check for local host
			if strings.HasPrefix(Host, "192.168") {
				//log.Printf("  *** non-SNI attempt at local host. Dropping request: [%s]\n", Host)
				return
			}

			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: Host,
					Host:   net.JoinHostPort(Host, "443"),
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
				Tlsfailure:	proxy.Tlsfailure,
				UpdateAllowedCounter:	proxy.UpdateAllowedCounter,
				UpdateBlockedCounter:	proxy.UpdateBlockedCounter,
				UpdateBlockedCounterByN:	proxy.UpdateBlockedCounterByN,
				UpdateBlockedHostsByN:	proxy.UpdateBlockedHostsByN,
				VerbosityLevel: proxy.VerbosityLevel,
				DeviceType: -1,
			}


			ctx.host = connectReq.URL.Host
			if strings.IndexRune(ctx.host, ':') == -1 {
				if connectReq.URL.Scheme == "http" {
					ctx.host += ":80"
				} else if connectReq.URL.Scheme == "https" {
					ctx.host += ":443"
				}
			}


			// We've sniffed the SNI record already through the vlshost muxer.
			// This just sets the flags to avoid throwing warnings.
			ctx.sniffedTLS = true
			ctx.sniHost = Host

			// Create a signature string for the accepted ciphers

			if tlsConn.ClientHelloMsg != nil && len(tlsConn.ClientHelloMsg.CipherSuites) > 0 {
				// RLS 10/10/2017 - Expanded signature
				// Generate a fingerprint for the client. This enables us to whitelist
				// failed TLS queries on a per-client basis.
				ctx.CipherSignature = GenerateSignature(tlsConn.ClientHelloMsg, false)

				// Use for debugging
				//if ctx.CipherSignature == "77cee627cc693c391194300c24b16295" {
				//	GenerateSignature(tlsConn.ClientHelloMsg, true)
				//}

				//ctx.Logf(2, "  *** cipher signature: %s", ctx.CipherSignature)
			} else {
				ctx.CipherSignature = ""
			}

			if proxy.Trace != nil {
				shouldTrace := proxy.Trace(ctx)
				if shouldTrace {
					setupTrace(ctx, "Modified Request")
					fmt.Printf("[TRACE] Dispatching original connect handlers to %+v\n", ctx.Req.URL)
				}
			}


			if ctx.Trace {
				fmt.Printf("[TRACE] CLIENTHELLO [%s] [Vers=%v] =\n%+v\n\n", ctx.CipherSignature, (*tlsConn.ClientHelloMsg).Vers, *tlsConn.ClientHelloMsg)
			}

			//log.Printf("*** ListenAndServeTLS 2 - ctx.host [%s]", ctx.host)
			proxy.dispatchConnectHandlers(ctx)

			// If tracing, run the same request but skip any filtering.
			if ctx.Trace {

				// Wait a little while for the original request to complete
				// TODO: Use a channel for this
				time.Sleep(10 * time.Second)

				fmt.Printf("[TRACE] Running parallel https request to %s\n", ctx.Req.URL)
				// Create a bidirectional, in-memory connection with fake client
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
					request, err := http.NewRequest("GET", Url, nil)

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

					_, err = ioutil.ReadAll(fakeresp.Body)
					if err != nil {
						fmt.Printf("[TRACE] Error while reading body. %+v\n", err)
						return
					}
					// Process the response and close
					//fmt.Printf("[TRACE] %s  resp.Body: %+v\n", status, string(body))


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
						UpdateAllowedCounter:        proxy.UpdateAllowedCounter,
						UpdateBlockedCounter:        proxy.UpdateBlockedCounter,
						UpdateBlockedCounterByN:        proxy.UpdateBlockedCounterByN,
						UpdateBlockedHostsByN:        proxy.UpdateBlockedHostsByN,
						VerbosityLevel: proxy.VerbosityLevel,
						DeviceType: -1,
						CipherSignature:        ctx.CipherSignature,
						sniffedTLS:             ctx.sniffedTLS,
						sniHost:                ctx.sniHost,
						host:			ctx.host,
						Trace:                  true,
						SkipRequestHandler:     true,
						SkipResponseHandler:    true,
					}

					setupTrace(ctxOrig, "Unmodified Request")
					fmt.Printf("[TRACE] Dispatching connect handlers to %+v\n", ctxOrig.Req.URL)
					proxy.dispatchConnectHandlers(ctxOrig)


				}
			}

		}(c)
	}
}

func GenerateSignature(h *vhost.ClientHelloMsg, debug bool) (string) {

	// Create string for cipher suites
	// These have to be sorted because the same client can return them in an arbitrary order
	var b bytes.Buffer
	var logbuf bytes.Buffer

	// For some reason, the first cipher signature is always a different number on the same client.
	// This may be a bug in vhost, so we'll skip it.
	i := 0
	for _, suite := range h.CipherSuites {
		if i > 0 {
			b.Write([]byte (strconv.Itoa(int(suite))))
		}

		if debug {
			logbuf.Write([]byte (strconv.Itoa(int(suite))))
			logbuf.Write([]byte ("-"))
		}

		i++
	}
	b.Write([]byte ("-"))

	// Create string for curves. The first value is often different for the same client, so we ignore it.
	i = 0
	for _, curve := range h.SupportedCurves {
		if i > 0 {
			b.Write([]byte (strconv.Itoa(int(curve))))
			//b.Write([]byte ("-"))
		}

		if debug {
			logbuf.Write([]byte (strconv.Itoa(int(curve))))
			logbuf.Write([]byte ("-"))
		}

		i++
	}
	b.Write([]byte ("-"))

	if debug {
		logbuf.Write([]byte ("-"))
	}

	for _, point := range h.SupportedPoints {
		b.Write([]byte (strconv.Itoa(int(point))))
	}
	b.Write([]byte ("-"))

	for _, comp := range h.CompressionMethods {
		b.Write([]byte (strconv.Itoa(int(comp))))
	}
	b.Write([]byte ("-"))

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
	signature := strconv.FormatUint(uint64(h.Vers), 10) + "-" + string(b.Bytes()) + "-" + OcspStapling  + "-" + ticketssupported + "-" + nextprotoneg

	// Note: this has to be compressed to avoid errors associated with too long filenames.
	hasher := md5.New()
	hasher.Write([]byte(signature))
	encodedsignature := hex.EncodeToString(hasher.Sum(nil))

	if debug {
		log.Printf("  *** detected target client: [%s] - [%s]\n", encodedsignature, signature)
	}

	//return signature
	return encodedsignature
}

// RLS 8/16/2017
// Logging now supports multiple levels of verbosity
func (proxy *ProxyHttpServer) Logf(level uint16, msg string, v ...interface{}) {
	// Todo: Find source of panics
	/*defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Error: Logging error (?). Proxy.Logger was nil?.", r)
			//panic("Aborting for analysis.")
		}
	}()*/
	if proxy.Logger != nil {
		if proxy.Verbose {}
			if level == 0 || proxy.VerbosityLevel&level != 0 {
				proxy.Logger.Printf(msg+"\n", v...)
			}
	}
}

// TODO: Refactor the logging functions into the Winston package
func (proxy *ProxyHttpServer) UpdateBlockedCounter() {
	proxy.UpdateBlockedCounterByN(1)
}

func (proxy *ProxyHttpServer) UpdateBlockedCounterByN(amount int) {
	//fmt.Printf("UpdateBlockedCounter...\n")

	if proxy.BlockedStats == nil {
		return
	}

	proxy.blockedmu.Lock()
	defer proxy.blockedmu.Unlock()

	// Convert today's date to a string
	key := time.Now().Format("2006-01-02")
	// Get the current count
	value, err := proxy.BlockedStats.Read(key)

	// If the entry doesn't exist, create it
	if err != nil {
		//fmt.Printf("UpdateBlockedCounter: previous value was 0\n")
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(amount))
		proxy.BlockedStats.Write(key, b)
	} else {
		//fmt.Printf("UpdateBlockedCounter: incrementing... %v\n", value)


		currentValue := binary.BigEndian.Uint64(value)
		//fmt.Printf("UpdateBlockedCounter: previous value %d\n", currentValue)
		// Convert from byte array to int, increment, then convert back
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, currentValue + uint64(amount))
		proxy.BlockedStats.WriteMem(key, b)
		//fmt.Printf("UpdateBlockedCounter: new value %d\n", currentValue + 1)
	}

}

func (proxy *ProxyHttpServer) UpdateAllowedCounter() {
	if proxy.AllowedStats == nil {
		return
	}
	// Convert today's date to a string
	key := time.Now().Format("2006-01-02")
	// Get the current count

	// Have to put this in mutex otherwise we end up in race conditions with other threads.
	// This leads to corrupted cache, broken cache and panics.
	proxy.allowedmu.Lock()
	defer proxy.allowedmu.Unlock()
	value, err := proxy.AllowedStats.Read(key)

	//fmt.Printf("\n\nRetrieved Allowed Stats... trying again. Was it cached?\n\n")
	//value, err = proxy.AllowedStats.Read(key)

	// If the entry doesn't exist, create it
	if err != nil {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, 1)
		proxy.AllowedStats.Write(key, b)
	} else {
		// Increment and save

		currentValue := binary.BigEndian.Uint64(value)
		//fmt.Printf("UpdateAllowedCounter: previous value %d\n", currentValue)
		// Convert from byte array to int, increment, then convert back
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, currentValue + 1)
		proxy.AllowedStats.WriteMem(key, b)
		//fmt.Printf("UpdateAllowedCounter: new value %d\n", currentValue + 1)
	}

}

// Call if the DNS blocks a page that was previously allowed through
func (proxy *ProxyHttpServer) DecrementAllowedCounter() {
	//fmt.Printf("DecrementAllowedCounter...\n")

	if proxy.AllowedStats == nil {
		return
	}

	// Convert today's date to a string
	key := time.Now().Format("2006-01-02")
	proxy.allowedmu.Lock()
	defer proxy.allowedmu.Unlock()

	// Get the current count
	value, err := proxy.AllowedStats.Read(key)

	// If the entry doesn't exist, create it
	if err != nil {
		//fmt.Printf("DecrementAllowedCounter: previous value was 0. Nothing to do.\n")

	} else {
		// Increment and save

		currentValue := binary.BigEndian.Uint64(value)
		// Convert from byte array to int, increment, then convert back
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, currentValue - 1)
		proxy.AllowedStats.WriteMem(key, b)
		//fmt.Printf("DecrementAllowedCounter: new value %d\n", currentValue - 1)

	}

}

func (proxy *ProxyHttpServer) UpdateBlockedHosts(host string, ) {
	proxy.UpdateBlockedHostsByN(host, 1)
}

// Increments the number of times we blocked a particular host
// This is used for reporting purposes.
func (proxy *ProxyHttpServer) UpdateBlockedHostsByN(host string, amount int) {
	//fmt.Printf("UpdateBlockedHosts...\n")


	if proxy.BlockedHosts == nil {
		return
	}

	proxy.blockedhostsmu.Lock()
	defer proxy.blockedhostsmu.Unlock()

	host = stripPort(host)

	// Get the current count
	value, err := proxy.BlockedHosts.Read(host)

	//proxy.Logf(1, "  *** blockedhost %s err=%+v", host, err)

	// TODO: Add error checking in case we get an invalid value. This could happen with a storage error.

	// If the entry doesn't exist, create it
	if err != nil {
		//fmt.Printf("UpdateBlockedHosts - host: [%s]\n", host)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(amount))
		proxy.BlockedHosts.Write(host, b)
	} else {
		//fmt.Printf("UpdateBlockedHosts: incrementing... %v\n", value)
		// Increment and save
		//fmt.Printf("UpdateBlockedHosts - host: [%s] [%d]\n", host, value)
		currentValue := binary.BigEndian.Uint64(value)

		//proxy.Logf(1, "  *** blockedhost %s currentvalue=%d", host, currentValue)

		//fmt.Printf("UpdateBlockedHosts: previous value %d\n", currentValue)
		// Convert from byte array to int, increment, then convert back
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, currentValue + uint64(amount))
		proxy.BlockedHosts.WriteMem(host, b)
		//fmt.Printf("UpdateBlockedHosts: new value %d\n", currentValue + 1)
	}

}


// SetMITMCertConfig sets the CA Config to be used to sign man-in-the-middle'd
// certificates. You can load some []byte with `LoadCAConfig()`. This bundle
// gets passed into the `ProxyCtx` and may be overridden in the [TODO:
// FIXME] `HandleConnect()` callback, before doing SNI sniffing.
func (proxy *ProxyHttpServer) SetMITMCertConfig(config *GoproxyConfig) {
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
