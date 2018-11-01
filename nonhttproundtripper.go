package goproxy

/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, June 2018
*/

/* Implements a minimal RoundTripper that can be used for non-http protocols over TLS.
 */

import (
	"net"
	"net/http"
	"fmt"
	"net/url"
	"strings"
	"crypto/tls"
	"errors"
	"time"
	"context"
	"golang.org/x/net/idna"
	"unicode/utf8"
	"io"
	"bufio"
	"sync"
	"compress/gzip"
	"container/list"
	"os"
)


var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")
const maxInt64 = 1<<63 - 1

type requestBodyReadError struct{ error }


type NonHTTPRoundTripper struct {
	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// Must be non-nil
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DialContext must be non-nil. The caller is responsible for providing this function.
	DialContext func (ctx context.Context, network string, addr string) (net.Conn, error)

	reqMu       sync.Mutex
	reqCanceler map[*http.Request]func(error)
	MaxResponseHeaderBytes int64
	idleMu     sync.Mutex
	idleLRU    connLRU
	idleConn   map[connectMethodKey][]*persistConn // most recently used at end
	idleConnCh map[connectMethodKey]chan *persistConn
	ExpectContinueTimeout time.Duration
	ResponseHeaderTimeout time.Duration

}

func (tr *NonHTTPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	ctx := req.Context()

	or := ctx.Value(NonHTTPRequest)
	if or == nil {
		return nil, fmt.Errorf("No request provided for non-http protocol request")
	}

	originalrequest := or.(*[]byte)

	for {
		treq := &transportRequest{Request: req}

		// TODO: Get connection
		cm, err := tr.connectMethodForRequest(treq)
		if err != nil {
			return nil, err
		}
		pconn, err := tr.getConn(treq, cm, originalrequest)
		if err != nil {
			//fmt.Printf("[DEBUG] NonHTTPRoundTripper() 3 err\n")
			tr.setReqCanceler(req, nil)
			return nil, err
		}
		fmt.Println("[DEBUG] pconn", pconn, "err", err)

		var resp *http.Response
		fmt.Println("[DEBUG] Custom RoundTripper() 3")
		resp, err = pconn.roundTrip(treq)
		fmt.Println("[DEBUG] Custom RoundTripper() 4")
		if err == nil {
			return resp, nil
		}
		if !pconn.shouldRetryRequest(req, err) {
			// Issue 16465: return underlying net.Conn.Read error from peek,
			// as we've historically done.
			if e, ok := err.(transportReadFromServerError); ok {
				err = e.err
			}
			return nil, err
		}
	}


	return nil, nil
}

func writerequest(r *http.Request, w io.Writer, originalrequest *[]byte) (err error) {

	// TODO: Just write the request to the writer!
	fmt.Printf("[DEBUG] writerequest(): \n%s\n", string(*originalrequest))


	// Wrap the writer in a bufio Writer if it's not already buffered.
	// Don't always call NewWriter, as that forces a bytes.Buffer
	// and other small bufio Writers to have a minimum 4k buffer
	// size.
	var bw *bufio.Writer

	if _, ok := w.(io.ByteWriter); !ok {
		bw = bufio.NewWriter(w)
		w = bw
	}

	// TODO: Write it here

	err = r.Write(w)

	//_, err = fmt.Fprintf(w, "%s %s HTTP/1.1\r\n")
	//n, err := w.Write(*originalrequest)
	if err != nil {
		fmt.Printf("[DEBUG] Writing request err:\n")
		return err
	}


	if bw, ok := w.(*bufio.Writer); ok {
		if err := bw.Flush(); err != nil {
			fmt.Printf("[DEBUG] Writing request err 2:\n")
			return err
		}
	}

	if bw != nil {
		return bw.Flush()
	}
	fmt.Printf("[DEBUG] Wrote request:\n")
	return nil
}


// transportRequest is a wrapper around a *Request that adds
// optional extra headers to write and stores any error to return
// from roundTrip.
type transportRequest struct {
	*http.Request                        // original request, not to be mutated
	extra    http.Header                 // extra headers to write, or nil

	mu  sync.Mutex // guards err
	err error      // first setError value for mapRoundTripError to consider
}

func (tr *transportRequest) extraHeaders() http.Header {
	if tr.extra == nil {
		tr.extra = make(http.Header)
	}
	return tr.extra
}

func (tr *transportRequest) setError(err error) {
	tr.mu.Lock()
	if tr.err == nil {
		tr.err = err
	}
	tr.mu.Unlock()
}

// shouldRetryRequest reports whether we should retry sending a failed
// HTTP request on a new connection. The non-nil input error is the
// error from roundTrip.
func (pc *persistConn) shouldRetryRequest(req *http.Request, err error) bool {
	/*if err == http2ErrNoCachedConn {
		// Issue 16582: if the user started a bunch of
		// requests at once, they can all pick the same conn
		// and violate the server's max concurrent streams.
		// Instead, match the HTTPS/1 behavior for now and dial
		// again to get a new TCP connection, rather than failing
		// this request.
		return true
	}*/
	if err == errMissingHost {
		// User error.
		return false
	}
	if !pc.isReused() {
		// This was a fresh connection. There's no reason the server
		// should've hung up on us.
		//
		// Also, if we retried now, we could loop forever
		// creating new connections and retrying if the server
		// is just hanging up on us because it doesn't like
		// our request (as opposed to sending an error).
		return false
	}
	if _, ok := err.(nothingWrittenError); ok {
		// We never wrote anything, so it's safe to retry, if there's no body or we
		// can "rewind" the body with GetBody.
		return outgoingLength(req) == 0 || req.GetBody != nil
	}
	if !isReplayable(req) {
		// Don't retry non-idempotent requests.
		return false
	}
	if _, ok := err.(transportReadFromServerError); ok {
		// We got some non-EOF net.Conn.Read failure reading
		// the 1st response byte from the server.
		return true
	}
	if err == errServerClosedIdle {
		// The server replied with io.EOF while we were trying to
		// read the response. Probably an unfortunately keep-alive
		// timeout, just as the client was writing a request.
		return true
	}
	return false // conservatively
}


// CancelRequest cancels an in-flight request by closing its connection.
// CancelRequest should only be called after RoundTrip has returned.
//
// Deprecated: Use Request.WithContext to create a request with a
// cancelable context instead. CancelRequest cannot cancel HTTP/2
// requests.
func (t *NonHTTPRoundTripper) CancelRequest(req *http.Request) {
	t.cancelRequest(req, errRequestCanceled)
}

// Cancel an in-flight request, recording the error value.
func (t *NonHTTPRoundTripper) cancelRequest(req *http.Request, err error) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	delete(t.reqCanceler, req)
	t.reqMu.Unlock()
	if cancel != nil {
		cancel(err)
	}
}

//
// Private implementation past this point.
//

var (
	httpProxyEnv = &envOnce{
		names: []string{"HTTP_PROXY", "http_proxy"},
	}
	httpsProxyEnv = &envOnce{
		names: []string{"HTTPS_PROXY", "https_proxy"},
	}
	noProxyEnv = &envOnce{
		names: []string{"NO_PROXY", "no_proxy"},
	}
)

// envOnce looks up an environment variable (optionally by multiple
// names) once. It mitigates expensive lookups on some platforms
// (e.g. Windows).
type envOnce struct {
	names []string
	once  sync.Once
	val   string
}

func (e *envOnce) Get() string {
	e.once.Do(e.init)
	return e.val
}

func (e *envOnce) init() {
	for _, n := range e.names {
		e.val = os.Getenv(n)
		if e.val != "" {
			return
		}
	}
}

// reset is used by tests
func (e *envOnce) reset() {
	e.once = sync.Once{}
	e.val = ""
}

func (t *NonHTTPRoundTripper) connectMethodForRequest(treq *transportRequest) (cm connectMethod, err error) {
	if port := treq.URL.Port(); !validPort(port) {
		return cm, fmt.Errorf("invalid URL port %q", port)
	}
	cm.targetScheme = treq.URL.Scheme
	cm.targetAddr = canonicalAddr(treq.URL)
	return cm, err
}


// error values for debugging and testing, not seen by users.
var (
	errKeepAlivesDisabled = errors.New("http: putIdleConn: keep alives disabled")
	errConnBroken         = errors.New("http: putIdleConn: connection is in bad state")
	errWantIdle           = errors.New("http: putIdleConn: CloseIdleConnections was called")
	errTooManyIdle        = errors.New("http: putIdleConn: too many idle connections")
	errTooManyIdleHost    = errors.New("http: putIdleConn: too many idle connections for host")
	errCloseIdleConns     = errors.New("http: CloseIdleConnections called")
	errReadLoopExiting    = errors.New("http: persistConn.readLoop exiting")
	errServerClosedIdle   = errors.New("http: server closed idle connection")
	errIdleConnTimeout    = errors.New("http: idle connection timeout")
	errNotCachingH2Conn   = errors.New("http: not caching alternate protocol's connections")
)

// transportReadFromServerError is used by Transport.readLoop when the
// 1 byte peek read fails and we're actually anticipating a response.
// Usually this is just due to the inherent keep-alive shut down race,
// where the server closed the connection at the same time the client
// wrote. The underlying err field is usually io.EOF or some
// ECONNRESET sort of thing which varies by platform. But it might be
// the user's custom net.Conn.Read error too, so we carry it along for
// them to return from Transport.RoundTrip.
type transportReadFromServerError struct {
	err error
}

func (e transportReadFromServerError) Error() string {
	return fmt.Sprintf("net/http: Transport failed to read from server: %v", e.err)
}

func (t *NonHTTPRoundTripper) putOrCloseIdleConn(pconn *persistConn) {
	if err := t.tryPutIdleConn(pconn); err != nil {
		pconn.close(err)
	}
}


// tryPutIdleConn adds pconn to the list of idle persistent connections awaiting
// a new request.
// If pconn is no longer needed or not in a good state, tryPutIdleConn returns
// an error explaining why it wasn't registered.
// tryPutIdleConn does not close pconn. Use putOrCloseIdleConn instead for that.
func (t *NonHTTPRoundTripper) tryPutIdleConn(pconn *persistConn) error {
	return errKeepAlivesDisabled
}

// getIdleConnCh returns a channel to receive and return idle
// persistent connection for the given connectMethod.
// It may return nil, if persistent connections are not being used.
func (t *NonHTTPRoundTripper) getIdleConnCh(cm connectMethod) chan *persistConn {
	return nil
}

func (t *NonHTTPRoundTripper) getIdleConn(cm connectMethod) (pconn *persistConn, idleSince time.Time) {
	return nil, time.Time{}
}

// removeIdleConn marks pconn as dead.
func (t *NonHTTPRoundTripper) removeIdleConn(pconn *persistConn) {
	return
}

func (t *NonHTTPRoundTripper) setReqCanceler(r *http.Request, fn func(error)) {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*http.Request]func(error))
	}
	if fn != nil {
		t.reqCanceler[r] = fn
	} else {
		delete(t.reqCanceler, r)
	}
}

// replaceReqCanceler replaces an existing cancel function. If there is no cancel function
// for the request, we don't set the function and return false.
// Since CancelRequest will clear the canceler, we can use the return value to detect if
// the request was canceled since the last setReqCancel call.
func (t *NonHTTPRoundTripper) replaceReqCanceler(r *http.Request, fn func(error)) bool {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	_, ok := t.reqCanceler[r]
	if !ok {
		return false
	}
	if fn != nil {
		t.reqCanceler[r] = fn
	} else {
		delete(t.reqCanceler, r)
	}
	return true
}

var zeroDialer net.Dialer

func (t *NonHTTPRoundTripper) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if t.DialContext != nil {
		return t.DialContext(ctx, network, addr)
	}
	return zeroDialer.DialContext(ctx, network, addr)
}

// getConn dials and creates a new persistConn to the target as
// specified in the connectMethod. This includes doing a proxy CONNECT
// and/or setting up TLS.  If this doesn't return an error, the persistConn
// is ready to write requests to.
func (t *NonHTTPRoundTripper) getConn(treq *transportRequest, cm connectMethod, originalrequest *[]byte) (*persistConn, error) {

	req := treq.Request
	ctx := req.Context()
	if pc, _ := t.getIdleConn(cm); pc != nil {
		// set request canceler to some non-nil function so we
		// can detect whether it was cleared between now and when
		// we enter roundTrip
		t.setReqCanceler(req, func(error) {})
		return pc, nil
	}

	type dialRes struct {
		pc  *persistConn
		err error
	}
	dialc := make(chan dialRes)

	// Copy these hooks so we don't race on the postPendingDial in
	// the goroutine we launch. Issue 11136.
	testHookPrePendingDial := testHookPrePendingDial
	testHookPostPendingDial := testHookPostPendingDial

	handlePendingDial := func() {
		testHookPrePendingDial()
		go func() {
			if v := <-dialc; v.err == nil {
				t.putOrCloseIdleConn(v.pc)
			}
			testHookPostPendingDial()
		}()
	}

	cancelc := make(chan error, 1)
	t.setReqCanceler(req, func(err error) { cancelc <- err })

	go func() {
		pc, err := t.dialConn(ctx, cm, originalrequest)
		dialc <- dialRes{pc, err}
	}()
	idleConnCh := t.getIdleConnCh(cm)
	select {
	case v := <-dialc:
	// Our dial finished.
		if v.pc != nil {
			return v.pc, nil
		}
			select {
			case <-req.Cancel:
			// It was an error due to cancelation, so prioritize that
			// error value. (Issue 16049)
				return nil, errRequestCanceledConn
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case err := <-cancelc:
				if err == errRequestCanceled {
					err = errRequestCanceledConn
				}
				return nil, err
			default:
			// It wasn't an error due to cancelation, so
			// return the original error message:
				return nil, v.err
			}
	case pc := <-idleConnCh:
	// Another request finished first and its net.Conn
	// became available before our dial. Or somebody
	// else's dial that they didn't use.
	// But our dial is still going, so give it away
	// when it finishes:
		handlePendingDial()
		return pc, nil
	case <-req.Cancel:
		handlePendingDial()
		return nil, errRequestCanceledConn
	case <-req.Context().Done():
		handlePendingDial()
		return nil, req.Context().Err()
	case err := <-cancelc:
		handlePendingDial()
		if err == errRequestCanceled {
			err = errRequestCanceledConn
		}
		return nil, err
	}
}

type oneConnDialer <-chan net.Conn

func (d oneConnDialer) Dial(network, addr string) (net.Conn, error) {
	select {
	case c := <-d:
		return c, nil
	default:
		return nil, io.EOF
	}
}

func (t *NonHTTPRoundTripper) dialConn(ctx context.Context, cm connectMethod, originalrequest *[]byte) (*persistConn, error) {
	pconn := &persistConn{
		t:             t,
		cacheKey:      cm.key(),
		reqch:         make(chan requestAndChan, 1),
		writech:       make(chan writeRequest, 1),
		closech:       make(chan struct{}),
		writeErrCh:    make(chan error, 1),
		writeLoopDone: make(chan struct{}),
	}

	//tlsDial := t.DialTLS != nil && cm.targetScheme == "nonhttps" && cm.proxyURL == nil
	/*if tlsDial {
		var err error
		pconn.conn, err = t.DialTLS("tcp", cm.addr())
		if err != nil {
			return nil, err
		}
		if pconn.conn == nil {
			return nil, errors.New("net/http: Transport.DialTLS returned (nil, nil)")
		}
		if tc, ok := pconn.conn.(*tls.Conn); ok {
			// Handshake here, in case DialTLS didn't. TLSNextProto below
			// depends on it for knowing the connection state.
			if err := tc.Handshake(); err != nil {
				go pconn.conn.Close()
				return nil, err
			}
			cs := tc.ConnectionState()
			pconn.tlsState = &cs
		}
	} else {*/
		conn, err := t.dial(ctx, "tcp", cm.addr())
		if err != nil {
			fmt.Printf("dialConn - err connecting %+v\n", err)
			return nil, err
		}
		pconn.conn = conn
	//}

	if cm.targetScheme == "nonhttps" {
		// Initiate TLS and check remote host name against certificate.
		cfg := cloneTLSConfig(t.TLSClientConfig)
		if cfg.ServerName == "" {
			cfg.ServerName = cm.tlsHost()
		}
		plainConn := pconn.conn
		tlsConn := tls.Client(plainConn, cfg)
		errc := make(chan error, 2)
		var timer *time.Timer // for canceling TLS handshake
		if d := t.TLSHandshakeTimeout; d != 0 {
			timer = time.AfterFunc(d, func() {
				errc <- tlsHandshakeTimeoutError{}
			})
		}
		go func() {
			err := tlsConn.Handshake()
			if timer != nil {
				timer.Stop()
			}
			fmt.Printf("dialConn - handshake err? (nil=handshake worked) %+v\n", err)
			errc <- err
		}()
		if err := <-errc; err != nil {
			fmt.Printf("dialConn - connection error %+v\n", err)
			plainConn.Close()
			return nil, err
		}
		if !cfg.InsecureSkipVerify {
			fmt.Printf("dialConn - checking certificate validity\n")
			if err := tlsConn.VerifyHostname(cfg.ServerName); err != nil {
				plainConn.Close()
				/*if trace != nil {
					fmt.Printf("*** KCPTransport.dialConn() - TLS Verify error=%+v\n", err)
				}*/
				return nil, err
			}
		}
		cs := tlsConn.ConnectionState()
		pconn.tlsState = &cs
		pconn.conn = tlsConn
	}

	/*if s := pconn.tlsState; s != nil && s.NegotiatedProtocolIsMutual && s.NegotiatedProtocol != "" {
		if next, ok := t.TLSNextProto[s.NegotiatedProtocol]; ok {
			*//*if trace != nil {
				fmt.Printf("*** KCPTransport.dialConn() - TLS handshake exit point 2\n")
			}*//*
			return &persistConn{alt: next(cm.targetAddr, pconn.conn.(*tls.Conn))}, nil
		}
	}*/

	pconn.br = bufio.NewReader(pconn)
	pconn.bw = bufio.NewWriter(persistConnWriter{pconn})
	/*if trace != nil {
		fmt.Printf("*** KCPTransport.dialConn() - pconn seems to be ok. Starting loops. \n")
	}*/
	//fmt.Printf("[DEBUG] dialConn() 4 - original request: %s\n\n", string(*originalrequest))
	go pconn.readLoop()
	go pconn.writeLoop(originalrequest)
	return pconn, nil
}

// persistConnWriter is the io.Writer written to by pc.bw.
// It accumulates the number of bytes written to the underlying conn,
// so the retry logic can determine whether any bytes made it across
// the wire.
// This is exactly 1 pointer field wide so it can go into an interface
// without allocation.
type persistConnWriter struct {
	pc *persistConn
}

func (w persistConnWriter) Write(p []byte) (n int, err error) {
	n, err = w.pc.conn.Write(p)
	w.pc.nwrite += int64(n)
	return
}

// useProxy reports whether requests to addr should use a proxy,
// according to the NO_PROXY or no_proxy environment variable.
// addr is always a canonicalAddr with a host and port.
func useProxy(addr string) bool {
	if len(addr) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return false
		}
	}

	no_proxy := noProxyEnv.Get()
	if no_proxy == "*" {
		return false
	}

	addr = strings.ToLower(strings.TrimSpace(addr))
	if hasPort(addr) {
		addr = addr[:strings.LastIndex(addr, ":")]
	}

	for _, p := range strings.Split(no_proxy, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}
		if hasPort(p) {
			p = p[:strings.LastIndex(p, ":")]
		}
		if addr == p {
			return false
		}
		if len(p) == 0 {
			// There is no host part, likely the entry is malformed; ignore.
			continue
		}
		if p[0] == '.' && (strings.HasSuffix(addr, p) || addr == p[1:]) {
			// no_proxy ".foo.com" matches "bar.foo.com" or "foo.com"
			return false
		}
		if p[0] != '.' && strings.HasSuffix(addr, p) && addr[len(addr)-len(p)-1] == '.' {
			// no_proxy "foo.com" matches "bar.foo.com"
			return false
		}
	}
	return true
}

// connectMethod is the map key (in its String form) for keeping persistent
// TCP connections alive for subsequent HTTP requests.
//
// A connect method may be of the following types:
//
// Cache key form                    Description
// -----------------                 -------------------------
// |http|foo.com                     http directly to server, no proxy
// |https|foo.com                    https directly to server, no proxy
// http://proxy.com|https|foo.com    http to proxy, then CONNECT to foo.com
// http://proxy.com|http             http to proxy, http to anywhere after that
// socks5://proxy.com|http|foo.com   socks5 to proxy, then http to foo.com
// socks5://proxy.com|https|foo.com  socks5 to proxy, then https to foo.com
//
// Note: no support to https to the proxy yet.
//
type connectMethod struct {
	proxyURL     *url.URL // nil for no proxy, else full proxy URL
	targetScheme string   // "http" or "https"
	targetAddr   string   // Not used if http proxy + http targetScheme (4th example in table)
}

func (cm *connectMethod) key() connectMethodKey {
	proxyStr := ""
	targetAddr := cm.targetAddr
	if cm.proxyURL != nil {
		proxyStr = cm.proxyURL.String()
		if strings.HasPrefix(cm.proxyURL.Scheme, "http") && cm.targetScheme == "http" {
			targetAddr = ""
		}
	}
	return connectMethodKey{
		proxy:  proxyStr,
		scheme: cm.targetScheme,
		addr:   targetAddr,
	}
}

// addr returns the first hop "host:port" to which we need to TCP connect.
func (cm *connectMethod) addr() string {
	if cm.proxyURL != nil {
		return canonicalAddr(cm.proxyURL)
	}
	return cm.targetAddr
}

// tlsHost returns the host name to match against the peer's
// TLS certificate.
func (cm *connectMethod) tlsHost() string {
	h := cm.targetAddr
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}
	return h
}

// connectMethodKey is the map key version of connectMethod, with a
// stringified proxy URL (or the empty string) instead of a pointer to
// a URL.
type connectMethodKey struct {
	proxy, scheme, addr string
}

func (k connectMethodKey) String() string {
	// Only used by tests.
	return fmt.Sprintf("%s|%s|%s", k.proxy, k.scheme, k.addr)
}

// persistConn wraps a connection, usually a persistent one
// (but may be used for non-keep-alive requests as well)
type persistConn struct {
					// alt optionally specifies the TLS NextProto RoundTripper.
					// This is used for HTTP/2 today and future protocols later.
					// If it's non-nil, the rest of the fields are unused.
	alt http.RoundTripper

	t         *NonHTTPRoundTripper
	cacheKey  connectMethodKey
	conn      net.Conn
	tlsState  *tls.ConnectionState
	br        *bufio.Reader       // from conn
	bw        *bufio.Writer       // to conn
	nwrite    int64               // bytes written
	reqch     chan requestAndChan // written by roundTrip; read by readLoop
	writech   chan writeRequest   // written by roundTrip; read by writeLoop
	closech   chan struct{}       // closed when conn closed
	isProxy   bool
	sawEOF    bool  // whether we've seen EOF from conn; owned by readLoop
	readLimit int64 // bytes allowed to be read; owned by readLoop
					// writeErrCh passes the request write error (usually nil)
					// from the writeLoop goroutine to the readLoop which passes
					// it off to the res.Body reader, which then uses it to decide
					// whether or not a connection can be reused. Issue 7569.
	writeErrCh chan error

	writeLoopDone chan struct{} // closed when write loop ends

					// Both guarded by Transport.idleMu:
	idleAt    time.Time   // time it last become idle
	idleTimer *time.Timer // holding an AfterFunc to close it

	mu                   sync.Mutex // guards following fields
	numExpectedResponses int
	closed               error // set non-nil when conn is closed, before closech is closed
	canceledErr          error // set non-nil if conn is canceled
	broken               bool  // an error has happened on this connection; marked broken so it's not reused.
	reused               bool  // whether conn has had successful request/response and is being reused.
					// mutateHeaderFunc is an optional func to modify extra
					// headers on each outbound request before it's written. (the
					// original Request given to RoundTrip is not modified)
	mutateHeaderFunc func(http.Header)
}

func (pc *persistConn) maxHeaderResponseSize() int64 {
	if v := pc.t.MaxResponseHeaderBytes; v != 0 {
		return v
	}
	return 10 << 20 // conservative default; same as http2
}

func (pc *persistConn) Read(p []byte) (n int, err error) {
	if pc.readLimit <= 0 {
		return 0, fmt.Errorf("read limit of %d bytes exhausted", pc.maxHeaderResponseSize())
	}
	if int64(len(p)) > pc.readLimit {
		p = p[:pc.readLimit]
	}
	n, err = pc.conn.Read(p)
	if err == io.EOF {
		pc.sawEOF = true
	}
	pc.readLimit -= int64(n)
	return
}

// isBroken reports whether this connection is in a known broken state.
func (pc *persistConn) isBroken() bool {
	pc.mu.Lock()
	b := pc.closed != nil
	pc.mu.Unlock()
	return b
}

// canceled returns non-nil if the connection was closed due to
// CancelRequest or due to context cancelation.
func (pc *persistConn) canceled() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.canceledErr
}

// isReused reports whether this connection is in a known broken state.
func (pc *persistConn) isReused() bool {
	pc.mu.Lock()
	r := pc.reused
	pc.mu.Unlock()
	return r
}

/*
func (pc *persistConn) gotIdleConnTrace(idleAt time.Time) (t httptrace.GotConnInfo) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	t.Reused = pc.reused
	t.Conn = pc.conn
	t.WasIdle = true
	if !idleAt.IsZero() {
		t.IdleTime = time.Since(idleAt)
	}
	return
}
*/

func (pc *persistConn) cancelRequest(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.canceledErr = err
	pc.closeLocked(errRequestCanceled)
}

// closeConnIfStillIdle closes the connection if it's still sitting idle.
// This is what's called by the persistConn's idleTimer, and is run in its
// own goroutine.
func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		// Not idle.
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

// t.idleMu must be held.
func (t *NonHTTPRoundTripper) removeIdleConnLocked(pconn *persistConn) {
	if pconn.idleTimer != nil {
		pconn.idleTimer.Stop()
	}
	t.idleLRU.remove(pconn)
	key := pconn.cacheKey
	pconns := t.idleConn[key]
	switch len(pconns) {
	case 0:
	// Nothing
	case 1:
		if pconns[0] == pconn {
			delete(t.idleConn, key)
		}
	default:
		for i, v := range pconns {
			if v != pconn {
				continue
			}
			// Slide down, keeping most recently-used
			// conns at the end.
			copy(pconns[i:], pconns[i+1:])
			t.idleConn[key] = pconns[:len(pconns)-1]
			break
		}
	}
}
// mapRoundTripError returns the appropriate error value for
// persistConn.roundTrip.
//
// The provided err is the first error that (*persistConn).roundTrip
// happened to receive from its select statement.
//
// The startBytesWritten value should be the value of pc.nwrite before the roundTrip
// started writing the request.
func (pc *persistConn) mapRoundTripError(req *transportRequest, startBytesWritten int64, err error) error {
	if err == nil {
		return nil
	}

	// If the request was canceled, that's better than network
	// failures that were likely the result of tearing down the
	// connection.
	if cerr := pc.canceled(); cerr != nil {
		return cerr
	}

	// See if an error was set explicitly.
	req.mu.Lock()
	reqErr := req.err
	req.mu.Unlock()
	if reqErr != nil {
		return reqErr
	}

	if err == errServerClosedIdle {
		// Don't decorate
		return err
	}

	if _, ok := err.(transportReadFromServerError); ok {
		// Don't decorate
		return err
	}
	if pc.isBroken() {
		<-pc.writeLoopDone
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return fmt.Errorf("net/http: HTTP/1.x transport connection broken: %v", err)
	}
	return err
}

func (pc *persistConn) readLoop() {
	closeErr := errReadLoopExiting // default value, if not changed below
	defer func() {
		fmt.Println("readloop - closing connection")
		pc.close(closeErr)
		pc.t.removeIdleConn(pc)
	}()

	tryPutIdleConn := func() bool {
		if err := pc.t.tryPutIdleConn(pc); err != nil {
			closeErr = err
			return false
		}
		return true
	}

	// eofc is used to block caller goroutines reading from Response.Body
	// at EOF until this goroutines has (potentially) added the connection
	// back to the idle pool.
	eofc := make(chan struct{})
	defer close(eofc) // unblock reader on errors

	// Read this once, before loop starts. (to avoid races in tests)
	testHookMu.Lock()
	testHookReadLoopBeforeNextRead := testHookReadLoopBeforeNextRead
	testHookMu.Unlock()

	alive := true
	for alive {
		pc.readLimit = pc.maxHeaderResponseSize()
		_, err := pc.br.Peek(1)

		pc.mu.Lock()
		if pc.numExpectedResponses == 0 {
			pc.readLoopPeekFailLocked(err)
			pc.mu.Unlock()
			return
		}
		pc.mu.Unlock()

		rc := <-pc.reqch

		fmt.Println("readloop - starting read logic")
		var resp *http.Response
		if err == nil {
			fmt.Println("readloop - about to read response")
			resp, err = pc.readResponse(rc)
			fmt.Println("readloop - finished reading response")
		} else {
			fmt.Println("readloop - Server didn't respond")
			err = transportReadFromServerError{err}
			closeErr = err
		}

		if err != nil {
			fmt.Printf("readloop - err: %+v\n", err)
			if pc.readLimit <= 0 {
				err = fmt.Errorf("net/http: server response headers exceeded %d bytes; aborted", pc.maxHeaderResponseSize())
			}

			select {
			case rc.ch <- responseAndError{err: err}:
			case <-rc.callerGone:
				return
			}
			return
		}
		pc.readLimit = maxInt64 // effictively no limit for response bodies

		pc.mu.Lock()
		pc.numExpectedResponses--
		pc.mu.Unlock()

		fmt.Println("readloop - 7")
		hasBody := rc.req.Method != "HEAD" && resp.ContentLength != 0

		if resp.Close || rc.req.Close || resp.StatusCode <= 199 {
			// Don't do keep-alive on error if either party requested a close
			// or we get an unexpected informational (1xx) response.
			// StatusCode 100 is already handled above.
			alive = false
		}

		fmt.Println("readloop - 8")
		if !hasBody {
			fmt.Println("readloop - 9")
			pc.t.setReqCanceler(rc.req, nil)

			// Put the idle conn back into the pool before we send the response
			// so if they process it quickly and make another request, they'll
			// get this same conn. But we use the unbuffered channel 'rc'
			// to guarantee that persistConn.roundTrip got out of its select
			// potentially waiting for this persistConn to close.
			// but after
			alive = alive &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn()

			select {
			case rc.ch <- responseAndError{res: resp}:
			case <-rc.callerGone:
				return
			}

			// Now that they've read from the unbuffered channel, they're safely
			// out of the select that also waits on this goroutine to die, so
			// we're allowed to exit now if needed (if alive is false)
			testHookReadLoopBeforeNextRead()
			continue
		}

		waitForBodyRead := make(chan bool, 2)
		body := &bodyEOFSignal{
			body: resp.Body,
			earlyCloseFn: func() error {
				waitForBodyRead <- false
				return nil

			},
			fn: func(err error) error {
				fmt.Println("readloop - 10")
				isEOF := err == io.EOF
				waitForBodyRead <- isEOF
				//TEST
				//if isEOF {
				//	err = nil
				//	isEOF = false
				//}
				if isEOF {
					<-eofc // see comment above eofc declaration
					fmt.Println("readloop - 11")
				} else if err != nil {
					fmt.Println("readloop - 12")
					if cerr := pc.canceled(); cerr != nil {
						return cerr
					}
				}
				return err
			},
		}
		fmt.Println("readloop - 13")
		resp.Body = body
		fmt.Println("readloop - 14")
		if rc.addedGzip && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			fmt.Println("readloop - 15")
			resp.Body = &gzipReader{body: body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}

		select {
		case rc.ch <- responseAndError{res: resp}:
		case <-rc.callerGone:
			return
		}

		fmt.Println("readloop - 16")
		// Before looping back to the top of this function and peeking on
		// the bufio.Reader, wait for the caller goroutine to finish
		// reading the response body. (or for cancelation or death)
		select {
		case bodyEOF := <-waitForBodyRead:
			pc.t.setReqCanceler(rc.req, nil) // before pc might return to idle pool
			alive = alive &&
				bodyEOF &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn()
			if bodyEOF {
				fmt.Println("readloop - 17")
				eofc <- struct{}{}
			}
		case <-rc.req.Cancel:
			alive = false
			fmt.Println("readloop - 18")
			pc.t.CancelRequest(rc.req)
		case <-rc.req.Context().Done():
			alive = false
			fmt.Println("readloop - 19")
			pc.t.cancelRequest(rc.req, rc.req.Context().Err())
		case <-pc.closech:
			fmt.Println("readloop - 20")
			alive = false
		}

		testHookReadLoopBeforeNextRead()
	}

}

func (pc *persistConn) readLoopPeekFailLocked(peekErr error) {
	if pc.closed != nil {
		return
	}
	//if n := pc.br.Buffered(); n > 0 {
	//	buf, _ := pc.br.Peek(n)
		//log.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", buf, peekErr)
	//}
	if peekErr == io.EOF {
		// common case.
		pc.closeLocked(errServerClosedIdle)
	} else {
		pc.closeLocked(fmt.Errorf("readLoopPeekFailLocked: %v", peekErr))
	}
}

// readResponse reads an HTTP response (or two, in the case of "Expect:
// 100-continue") from the server. It returns the final non-100 one.
// trace is optional.
func (pc *persistConn) readResponse(rc requestAndChan) (resp *http.Response, err error) {
	// TODO: Just read the response and put it all in body. The caller will be responsible for forwarding back to the client.
	resp, err = http.ReadResponse(pc.br, rc.req)
	if err != nil {
		fmt.Printf("readResponse - couldn't read response: %+v\n", err)
		return
	}
	if rc.continueCh != nil {
		if resp.StatusCode == 100 {
			rc.continueCh <- struct{}{}
		} else {
			close(rc.continueCh)
		}
	}
	if resp.StatusCode == 100 {
		pc.readLimit = pc.maxHeaderResponseSize() // reset the limit
		resp, err = http.ReadResponse(pc.br, rc.req)
		if err != nil {
			return
		}
	}
	resp.TLS = pc.tlsState
	return
}

// waitForContinue returns the function to block until
// any response, timeout or connection close. After any of them,
// the function returns a bool which indicates if the body should be sent.
func (pc *persistConn) waitForContinue(continueCh <-chan struct{}) func() bool {
	if continueCh == nil {
		return nil
	}
	return func() bool {
		timer := time.NewTimer(pc.t.ExpectContinueTimeout)
		defer timer.Stop()

		select {
		case _, ok := <-continueCh:
			return ok
		case <-timer.C:
			return true
		case <-pc.closech:
			return false
		}
	}
}

// nothingWrittenError wraps a write errors which ended up writing zero bytes.
type nothingWrittenError struct {
	error
}

func (pc *persistConn) writeLoop(originalrequest *[]byte) {
	defer close(pc.writeLoopDone)
	for {
		select {
		case wr := <-pc.writech:
			startBytesWritten := pc.nwrite
		fmt.Printf("[DEBUG] writeLoop - originalrequest: %s\n\n", string(*originalrequest))
			err := writerequest(wr.req.Request, pc.bw, originalrequest)
			if bre, ok := err.(requestBodyReadError); ok {
				err = bre.error
				// Errors reading from the user's
				// Request.Body are high priority.
				// Set it here before sending on the
				// channels below or calling
				// pc.close() which tears town
				// connections and causes other
				// errors.
				wr.req.setError(err)
			}
			if err == nil {
				err = pc.bw.Flush()
				fmt.Println("writeLoop - flushed")
			}
			if err != nil {
				if pc.nwrite == startBytesWritten {
					err = nothingWrittenError{err}
				}
			}
			pc.writeErrCh <- err // to the body reader, which might recycle us
			wr.ch <- err         // to the roundTrip function
			fmt.Println("writeLoop - probably written successfully")
			if err != nil {
				fmt.Println("writeLoop - error / closed")
				pc.close(err)
				return
			}
		case <-pc.closech:
			fmt.Println("writeLoop - close")
			return
		}
	}
}

// wroteRequest is a check before recycling a connection that the previous write
// (from writeLoop above) happened and was successful.
func (pc *persistConn) wroteRequest() bool {
	select {
	case err := <-pc.writeErrCh:
		fmt.Println("wroteRequest error")
	// Common case: the write happened well before the response, so
	// avoid creating a timer.
		return err == nil
	default:
	// Rare case: the request was written in writeLoop above but
	// before it could send to pc.writeErrCh, the reader read it
	// all, processed it, and called us here. In this case, give the
	// write goroutine a bit of time to finish its send.
	//
	// Less rare case: We also get here in the legitimate case of
	// Issue 7569, where the writer is still writing (or stalled),
	// but the server has already replied. In this case, we don't
	// want to wait too long, and we want to return false so this
	// connection isn't re-used.
			select {
			case err := <-pc.writeErrCh:
				return err == nil
			case <-time.After(50 * time.Millisecond):
				return false
			}
	}
}

// responseAndError is how the goroutine reading from an HTTP/1 server
// communicates with the goroutine doing the RoundTrip.
type responseAndError struct {
	res *http.Response // else use this response (see res method)
	err error
}

type requestAndChan struct {
	req *http.Request
	ch  chan responseAndError // unbuffered; always send in select on callerGone

				  // whether the Transport (as opposed to the user client code)
				  // added the Accept-Encoding gzip header. If the Transport
				  // set it, only then do we transparently decode the gzip.
	addedGzip bool

				  // Optional blocking chan for Expect: 100-continue (for send).
				  // If the request has an "Expect: 100-continue" header and
				  // the server responds 100 Continue, readLoop send a value
				  // to writeLoop via this chan.
	continueCh chan<- struct{}

	callerGone <-chan struct{} // closed when roundTrip caller has returned
}

// A writeRequest is sent by the readLoop's goroutine to the
// writeLoop's goroutine to write a request while the read loop
// concurrently waits on both the write response and the server's
// reply.
type writeRequest struct {
	req *transportRequest
	ch  chan<- error

	// Optional blocking chan for Expect: 100-continue (for receive).
	// If not nil, writeLoop blocks sending request body until
	// it receives from this chan.
	continueCh <-chan struct{}
}

type httpError struct {
	err     string
	timeout bool
}

func (e *httpError) Error() string   { return e.err }
func (e *httpError) Timeout() bool   { return e.timeout }
func (e *httpError) Temporary() bool { return true }

var errTimeout error = &httpError{err: "net/http: timeout awaiting response headers", timeout: true}
var errRequestCanceled = errors.New("net/http: request canceled")
var errRequestCanceledConn = errors.New("net/http: request canceled while waiting for connection") // TODO: unify?

func nop() {}

// testHooks. Always non-nil.
var (
	testHookEnterRoundTrip   = nop
	testHookWaitResLoop      = nop
	testHookRoundTripRetried = nop
	testHookPrePendingDial   = nop
	testHookPostPendingDial  = nop

	testHookMu                     sync.Locker = fakeLocker{} // guards following
	testHookReadLoopBeforeNextRead             = nop
)

func (pc *persistConn) roundTrip(req *transportRequest) (resp *http.Response, err error) {
	fmt.Printf("[DEBUG] pconn.roundTrip() - 1\n")
	if !pc.t.replaceReqCanceler(req.Request, pc.cancelRequest) {
		pc.t.putOrCloseIdleConn(pc)
		return nil, errRequestCanceled
	}
	pc.mu.Lock()
	pc.numExpectedResponses++
	//headerFn := pc.mutateHeaderFunc
	pc.mu.Unlock()

	//if headerFn != nil {
	//	headerFn(req.extraHeaders())
	//}

	// Ask for a compressed version if the caller didn't set their
	// own value for Accept-Encoding. We only attempt to
	// uncompress the gzip stream if we were the layer that
	// requested it.
/*	requestedGzip := false
	if !pc.t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: http://www.gzip.org/zlib/zlib_faq.html#faq38
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   http://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		requestedGzip = true
		req.extraHeaders().Set("Accept-Encoding", "gzip")
	}*/

	var continueCh chan struct{}
	//if req.ProtoAtLeast(1, 1) && req.Body != nil && expectsContinue(req) {
	//	continueCh = make(chan struct{}, 1)
	//}

	//if pc.t.DisableKeepAlives {
	//	req.extraHeaders().Set("Connection", "close")
	//}

	fmt.Printf("[DEBUG] pconn.roundTrip() - 2\n")
	gone := make(chan struct{})
	defer close(gone)

	defer func() {
		if err != nil {
			pc.t.setReqCanceler(req.Request, nil)
		}
	}()

	const debugRoundTrip = true

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	fmt.Printf("[DEBUG] pconn.roundTrip() - 3\n")
	pc.writech <- writeRequest{req, writeErrCh, continueCh}
	fmt.Printf("[DEBUG] pconn.roundTrip() - 4\n")
	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		req:        req.Request,
		ch:         resc,
		//addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	var respHeaderTimer <-chan time.Time
	cancelChan := req.Request.Cancel
	ctxDoneChan := req.Context().Done()
	for {
		testHookWaitResLoop()
		select {
		case err := <-writeErrCh:
			if debugRoundTrip {
				req.logf("writeErrCh resv: %T/%#v", err, err)
			}
			if err != nil {
				pc.close(fmt.Errorf("write error: %v", err))
				return nil, pc.mapRoundTripError(req, startBytesWritten, err)
			}
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				if debugRoundTrip {
					req.logf("starting timer for %v", d)
				}
				timer := time.NewTimer(d)
				defer timer.Stop() // prevent leaks
				respHeaderTimer = timer.C
			}
		case <-pc.closech:
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			if (re.res == nil) == (re.err == nil) {
				panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
			}
			if debugRoundTrip {
				req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
			}
			if re.err != nil {
				return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
			}
			return re.res, nil
		case <-cancelChan:
			pc.t.CancelRequest(req.Request)
			cancelChan = nil
		case <-ctxDoneChan:
			pc.t.cancelRequest(req.Request, req.Context().Err())
			cancelChan = nil
			ctxDoneChan = nil
		}
	}
}

// tLogKey is a context WithValue key for test debugging contexts containing
// a t.Logf func. See export_test.go's Request.WithT method.
type tLogKey struct{}

func (r *transportRequest) logf(format string, args ...interface{}) {
	if logf, ok := r.Request.Context().Value(tLogKey{}).(func(string, ...interface{})); ok {
		logf(time.Now().Format(time.RFC3339Nano)+": "+format, args...)
	}
}

// markReused marks this connection as having been successfully used for a
// request and response.
func (pc *persistConn) markReused() {
	pc.mu.Lock()
	pc.reused = true
	pc.mu.Unlock()
}

// close closes the underlying TCP connection and closes
// the pc.closech channel.
//
// The provided err is only for testing and debugging; in normal
// circumstances it should never be seen by users.
func (pc *persistConn) close(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.closeLocked(err)
}

func (pc *persistConn) closeLocked(err error) {
	if err == nil {
		panic("nil error")
	}
	pc.broken = true
	if pc.closed == nil {
		pc.closed = err
		if pc.alt != nil {
			// Do nothing; can only get here via getConn's
			// handlePendingDial's putOrCloseIdleConn when
			// it turns out the abandoned connection in
			// flight ended up negotiating an alternate
			// protocol. We don't use the connection
			// freelist for http2. That's done by the
			// alternate protocol's RoundTripper.
		} else {
			pc.conn.Close()
			close(pc.closech)
		}
	}
	pc.mutateHeaderFunc = nil
}

var portMap = map[string]string{
	"nonhttp":   "80",
	"nonhttps":  "443",
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

// bodyEOFSignal is used by the HTTP/1 transport when reading response
// bodies to make sure we see the end of a response body before
// proceeding and reading on the connection again.
//
// It wraps a ReadCloser but runs fn (if non-nil) at most
// once, right before its final (error-producing) Read or Close call
// returns. fn should return the new error to return from Read or Close.
//
// If earlyCloseFn is non-nil and Close is called before io.EOF is
// seen, earlyCloseFn is called instead of fn, and its return value is
// the return value from Close.
type bodyEOFSignal struct {
	body         io.ReadCloser
	mu           sync.Mutex        // guards following 4 fields
	closed       bool              // whether Close has been called
	rerr         error             // sticky Read error
	fn           func(error) error // err will be nil on Read io.EOF
	earlyCloseFn func() error      // optional alt Close func used if io.EOF not seen
}

var errReadOnClosedResBody = errors.New("http: read on closed response body")

func (es *bodyEOFSignal) Read(p []byte) (n int, err error) {
	es.mu.Lock()
	closed, rerr := es.closed, es.rerr
	es.mu.Unlock()
	if closed {
		return 0, errReadOnClosedResBody
	}
	if rerr != nil {
		return 0, rerr
	}

	n, err = es.body.Read(p)
	if err != nil {
		es.mu.Lock()
		defer es.mu.Unlock()
		if es.rerr == nil {
			es.rerr = err
		}
		err = es.condfn(err)
	}
	return
}

func (es *bodyEOFSignal) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.closed {
		return nil
	}
	es.closed = true
	if es.earlyCloseFn != nil && es.rerr != io.EOF {
		return es.earlyCloseFn()
	}
	err := es.body.Close()
	return es.condfn(err)
}

// caller must hold es.mu.
func (es *bodyEOFSignal) condfn(err error) error {
	if es.fn == nil {
		return err
	}
	err = es.fn(err)
	es.fn = nil
	return err
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type gzipReader struct {
	body *bodyEOFSignal // underlying HTTP/1 response body framing
	zr   *gzip.Reader   // lazily-initialized gzip reader
	zerr error          // any error from gzip.NewReader; sticky
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	if gz.zr == nil {
		if gz.zerr == nil {
			gz.zr, gz.zerr = gzip.NewReader(gz.body)
		}
		if gz.zerr != nil {
			return 0, gz.zerr
		}
	}

	gz.body.mu.Lock()
	if gz.body.closed {
		err = errReadOnClosedResBody
	}
	gz.body.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return gz.zr.Read(p)
}

func (gz *gzipReader) Close() error {
	return gz.body.Close()
}

type readerAndCloser struct {
	io.Reader
	io.Closer
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// fakeLocker is a sync.Locker which does nothing. It's used to guard
// test-only fields when not under test, to avoid runtime atomic
// overhead.
type fakeLocker struct{}

func (fakeLocker) Lock()   {}
func (fakeLocker) Unlock() {}

// clneTLSConfig returns a shallow clone of cfg, or a new zero tls.Config if
// cfg is nil. This is safe to call even if cfg is in active use by a TLS
// client or server.
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

type connLRU struct {
	ll *list.List // list.Element.Value type is of *persistConn
	m  map[*persistConn]*list.Element
}

// add adds pc to the head of the linked list.
func (cl *connLRU) add(pc *persistConn) {
	if cl.ll == nil {
		cl.ll = list.New()
		cl.m = make(map[*persistConn]*list.Element)
	}
	ele := cl.ll.PushFront(pc)
	if _, ok := cl.m[pc]; ok {
		panic("persistConn was already in LRU")
	}
	cl.m[pc] = ele
}

func (cl *connLRU) removeOldest() *persistConn {
	ele := cl.ll.Back()
	pc := ele.Value.(*persistConn)
	cl.ll.Remove(ele)
	delete(cl.m, pc)
	return pc
}

// remove removes pc from cl.
func (cl *connLRU) remove(pc *persistConn) {
	if ele, ok := cl.m[pc]; ok {
		cl.ll.Remove(ele)
		delete(cl.m, pc)
	}
}

// len returns the number of items in the cache.
func (cl *connLRU) len() int {
	return len(cl.m)
}

// validPort reports whether p (without the colon) is a valid port in
// a URL, per RFC 3986 Section 3.2.3, which says the port may be
// empty, or only contain digits.
func validPort(p string) bool {
	for _, r := range []byte(p) {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// outgoingLength reports the Content-Length of this outgoing (Client) request.
// It maps 0 into -1 (unknown) when the Body is non-nil.
func outgoingLength(r *http.Request) int64 {
	if r.Body == nil || r.Body == http.NoBody {
		return 0
	}

	if r.ContentLength != 0 {
		return r.ContentLength
	}

	return -1
}

func isReplayable(r *http.Request) bool {
	return true
}

func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if isASCII(v) {
		return v, nil
	}

	return idna.Lookup.ToASCII(v)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}