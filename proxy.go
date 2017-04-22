package goproxy

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/abourget/goproxy/har"
)

// The basic proxy type. Implements http.Handler.
type ProxyHttpServer struct {
	// session variable must be aligned in i386
	// see http://golang.org/src/pkg/sync/atomic/doc.go#L41
	sess int64
	// setting Verbose to true will log information on each request sent to the proxy
	Verbose bool
	// SniffSNI enables sniffing Server Name Indicator when doing CONNECT calls.  It will thus answer to CONNECT calls with a "200 OK" even if the remote server might not answer.  The result would be the shutdown of the connection instead of an appropriate HTTP error code if the remote node doesn't answer.
	SniffSNI bool
	Logger   *log.Logger

	// Registered handlers
	connectHandlers  []Handler
	requestHandlers  []Handler
	responseHandlers []Handler
	doneHandlers     []Handler

	// NonProxyHandler will be used to handle direct connections to the proxy. You can assign an `http.ServeMux` or some other routing libs here.  The default will return a 500 error saying this is a proxy and has nothing to serve by itself.
	NonProxyHandler http.Handler

	// Logging and round-tripping
	harLog            *har.Har
	harLogEntryCh     chan harReqAndResp
	harFlushRequest   chan string
	harFlushToMemory  chan chan *har.Har
	harFlusherRunOnce sync.Once

	// Custom transport to be used
	Transport *http.Transport

	// Setting MITMCertConfig allows you to override the default CA cert/key used to sign MITM'd requests.
	MITMCertConfig *GoproxyConfig

	// ConnectDial will be used to create TCP connections for CONNECT requests
	// if nil, .Transport.Dial will be used
	ConnectDial func(network string, addr string) (net.Conn, error)
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
		Transport: &http.Transport{
			TLSClientConfig: tlsClientSkipVerify,
			Proxy:           http.ProxyFromEnvironment,
		},
		MITMCertConfig:  GoproxyCaConfig,
		harLog:          har.New(),
		harLogEntryCh:   make(chan harReqAndResp, 10),
		harFlushRequest: make(chan string, 10),
		harFlushToMemory: make(chan chan *har.Har, 10),
	}
	proxy.ConnectDial = dialerFromEnv(&proxy)
	return &proxy
}

// Standard net/http function. Shouldn't be used directly, http.Serve will use it.
func (proxy *ProxyHttpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//r.Header["X-Forwarded-For"] = w.RemoteAddr()

	ctx := &ProxyCtx{
		Method:         r.Method,
		SourceIP:       r.RemoteAddr, // pick it from somewhere else ? have a plugin to override this ?
		Req:            r,
		ResponseWriter: w,
		UserData:       make(map[string]string),
		UserObjects:    make(map[string]interface{}),
		Session:        atomic.AddInt64(&proxy.sess, 1),
		proxy:          proxy,
		MITMCertConfig: proxy.MITMCertConfig,
	}
	ctx.host = r.URL.Host
	if strings.IndexRune(ctx.host, ':') == -1 {
		if r.URL.Scheme == "http" {
			ctx.host += ":80"
		} else if r.URL.Scheme == "https" {
			ctx.host += ":443"
		}
	}

	if r.Method == "CONNECT" {
		proxy.dispatchConnectHandlers(ctx)
	} else {
		ctx.Logf("Got request %v %v %v %v", r.URL.Path, r.Host, r.Method, r.URL.String())
		if !r.URL.IsAbs() {
			proxy.NonProxyHandler.ServeHTTP(w, r)
			return
		}

		proxy.dispatchRequestHandlers(ctx)
	}
}

// ListenAndServe launches all the servers required and listens. Use this method if you want to start listeners for transparent proxying.
func (proxy *ProxyHttpServer) ListenAndServe(addr string) error {
	// TODO: implement listening on a port for HTTP transparent proxying
	// TODO: implement listening on a port for HTTPS transparent proxying

	return http.ListenAndServe(addr, proxy)
}

func (proxy *ProxyHttpServer) Logf(msg string, v ...interface{}) {
	if proxy.Verbose {
		proxy.Logger.Printf("INFO: "+msg+"\n", v...)
	}
}

// SetMITMCertConfig sets the CA Config to be used to sign man-in-the-middle'd
// certificates. You can load some []byte with `LoadCAConfig()`. This bundle
// gets passed into the `ProxyCtx` and may be overridden in the [TODO:
// FIXME] `HandleConnect()` callback, before doing SNI sniffing.
func (proxy *ProxyHttpServer) SetMITMCertConfig(config *GoproxyConfig) {
	proxy.MITMCertConfig = config
}
