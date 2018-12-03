/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, July 2018
*/

/* ShadowTransport is a KCP replacement for the standard transport package which handles connection
 * requests and roundtrips via the Winston private mesh network. It is tightly coupled with ShadowNetwork.
 */

package shadownetwork

import (
	"time"
	kcp "github.com/winstonprivacyinc/kcp-go"
	"github.com/winstonprivacyinc/smux"
	"net/http"
	"sync"
	"context"
	"net"
	"fmt"
	"strconv"
	"github.com/pkg/errors"
	"sync/atomic"
	"strings"
	"encoding/binary"
	"net/url"
	"crypto/tls"
	//"net/http/httptrace"
	"bufio"
	//"net/http/httputil"
	//"io/ioutil"
)

const ErrorRefusedConnection = "Remote peer closed connection."
const ErrorExceededBandwidth = "Exceeded allocated bandwidth for this password interval"
const ErrorConnectionFailed = "Connection to remote peer failed."
const ErrorExpiredTransport = "Transport password has expired."

const maxConnectionErrors = 7		// Maximum number of successive connection errors before we deactivate remote peer

// Used to pass errors back from DialContext
const ShadowTransportFailed = "ShadowTransportFailed"
type ShadowNetworkFailure struct {
	Failed	bool
}

// Represents an outgoing connection to remote peer. Differs from ShadowPeer, in that the latter contains
// information on incoming peers which connect to ShadowServer. Keyed by IP:Port.
type ShadowTransport struct {

	ID			string			// The enode of the remote peer
	RemoteIP		string
	AltIP			string			// Used for unit testing only. Allows us to assign an alternate IP address to the same transport for reverse peer lookup.
	Transport 		http.RoundTripper
	Available		bool			// If false, node will be ignored
	FailureReason		string			// Explanation for more recent connection failure
	ConnectionErrors	int			// # of successive connecton errors. Multiple errors will deactivate the transport.
	GoodUntil		time.Time		// Only use up to this time
	AuthReqsSent		int			// Records # of successive AuthReqs sent without a response
	NextAuthReq		time.Time		// Used to throttle AuthReq messages for expired transports
	Port			string			// The primary listening port of the remote node
	Password		Password		// Password of remote node
	Cipher           	*kcp.BlockCrypt

	// Bandwidth (bytes/sec) currently allocated to this transport.
	// The maximum number of bytes allowed for a given AuthResp is equal to (Bandwidth * Expiration seconds).
	// If this is exceeded, the remote connection will stop responding until the next password reset.
	Bandwidth		int
	Config			*ShadowServerConfig	// Contains low level kcptun settings
	smuxConfig		*smux.Config		// kcp session config settings
	muxes 			[]struct{		// manages concurrent connections to the remote peer
		session *smux.Session
		ttl     time.Time
	}
	chScavenger 		chan *smux.Session	// channel to receive session scavenger requests
	rr			uint16			// request counter
	network       		*ShadowNetwork 			// pointer to the parent ShadowNetwork

	LastVerification	time.Time		// Last time the peer was verified.
	Renegotiate		bool			// Set to true to force a transport to restart a session. Used for unit testing password changes.
	mu			sync.RWMutex

	AllowInternalRequests	bool			// Allow internal IP requests to go over Shadow Network. Used for unit testing.
}

type Password struct {
	// Important: Fields which require atomic access must be declared first in the structure to ensure that they are aligned properly.
	// https://stackoverflow.com/questions/28670232/atomic-addint64-causes-invalid-memory-address-or-nil-pointer-dereference
	Borrowed		uint64			// Bandwidth used by this transport for current password

	Password		string
							//Created		time.Time
	NotBefore		time.Time
	NotAfter		time.Time
	AllocatedBytes		uint64			// maximum # of bytes which can be borrowed for the current password
	mu			sync.RWMutex
}



// Checks to see if the transport has expired. If it has, sets Available to false.
func (st *ShadowTransport) IsAvailable() (bool) {
	if st.GoodUntil.Before(time.Now().Local()) {
		// Only record an error if the transport is marked as available.
		if st.Available {
			st.RecordFailedConnection(ErrorExpiredTransport)
		}
		return false
	}

	return true
}


// Callback to let a transport know of a connection error. Multiple failures will result in the
// transport being marked as unavailable.
func (st *ShadowTransport) RecordFailedConnection(reason string) {
	// A common connection failure is "n=0 socket closed". This can indicate a cipher error but more likely it is
	// due to the server closing the original pipe to a force a new one to be opened. This can happen with every open pipe
	// so don't deactivate the transport unless we get a rapid sequence of them without any bytes received in between.

	// Context Canceled means that the client closed the connection. These errors don't count.
	if strings.Contains(reason, "context canceled") {
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	st.ConnectionErrors++
	st.FailureReason = reason
	if st.ConnectionErrors >= maxConnectionErrors || reason == ErrorExceededBandwidth {
		//fmt.Println("[DEBUG] Transport has too many connection errors. Setting unavailable.", st.RemoteIP, "error", reason, "# errors", st.ConnectionErrors)
		st.Available = false

		// If the error was a broken pipe, the deactivate the transport for 30 minutes to avoid
		// broken responses and delays.
		if reason == ErrorConnectionFailed {
			fmt.Println("[DEBUG] Broken Pipe error - deactivating transport for 30 minutes.")
			st.GoodUntil = time.Now().Local().Add(time.Minute * 30)
		}

	}
	//fmt.Printf("[ERROR] Connection failed to remote peer - reason: %s [%d]\n", reason, st.ConnectionErrors)

}

// Cleans up references so garbage collection will work properly. Call this when closing down transports.
func (t *ShadowTransport) Close()  {
	//t.Transport.(*KCPTransport).Transport = nil
	t.Transport.(*KCPTransport).PrivateTransport = nil

	for _, v := range t.muxes {
		v.session.Close()
	}
}

// Closes and deletes any existing sessions, replacing them with newly initialized ones
// Important: Caller should hold lock around sn.mu before calling to protect n.muxes[].session
func initializeSessions(n *ShadowTransport, expiresSec int) {
	//fmt.Printf("[DEBUG] [%s] ShadowNetwork - InitializeSessions()\n", n.network.Name[0:10])
	// Close existing sessions
	for _, sess := range n.muxes {
		sess.session.Close()
		//fmt.Printf("[DEBUG] [%s] ShadowNetwork.initializeSessions() - closing existing session and all streams.\n")
	}


	numconn := uint16(n.Config.Conn)
	n.muxes = make([]struct {
		session *smux.Session
		ttl     time.Time
	}, numconn)

	for k := range n.muxes {
		n.muxes[k].session = n.waitConn()
		// Set the TTL to ensure that the session is not kept open after the password expires
		n.muxes[k].ttl = time.Now().Add(time.Duration(expiresSec) * time.Second)

		//fmt.Println("[INFO] ShadowNetwork.initializeSessions() - Opened a new session with remote peer.")
	}

}


// Function used to establish a new connection to a remote peer
func (tr *ShadowTransport) createConn() (*smux.Session, error) {
	//fmt.Printf("[DEBUG] ShadowTransport.createConn() - cipher: %+v\n", *tr.Cipher)
	localaddr := ""


	// Send in random local address. This allows unit tests to run peers on different IPs.
	if tr.network.ListenAddr != "" {
		freeport, err := getFreePort()
		if err == nil {
			localaddr = tr.network.ListenAddr + ":" + strconv.Itoa(freeport)
		}
		//fmt.Printf("[DEBUG] [%s] Setting local outgoing KCP address to %s\n", tr.network.Name[0:10], localaddr)
	}

	//fmt.Printf("[DEBUG] createConn - generating new cipher for transport [%s]\n", tr.Password.Password)
	config := GetServerConfig()
	tr.Cipher = tr.network.ShadowServer.generateBlock(tr.Password.Password, config.Crypt)

	kcpconn, err := kcp.DialWithOptions(tr.RemoteIP + ":" + tr.Port, localaddr, *tr.Cipher, tr.Config.DataShard, tr.Config.ParityShard)



	if err != nil {
		return nil, errors.Wrap(err, "createConn()")
	}
	//fmt.Printf("[DEBUG] ShdowTransport.createConn() - created new kcp connection to %s\n", tr.RemoteIP + ":" + tr.Port)
	kcpconn.SetStreamMode(true)
	kcpconn.SetWriteDelay(true)
	kcpconn.SetNoDelay(tr.Config.NoDelay, tr.Config.Interval, tr.Config.Resend, tr.Config.NoCongestion)
	kcpconn.SetWindowSize(tr.Config.SndWnd, tr.Config.RcvWnd)
	kcpconn.SetMtu(tr.Config.MTU)
	kcpconn.SetACKNoDelay(tr.Config.AckNodelay)

	kcpconn.ReadMeter = tr.RecordBorrowed

	if err := kcpconn.SetDSCP(tr.Config.DSCP); err != nil {
		fmt.Printf("SetDSCP: %+v\n", err)
	}
	if err := kcpconn.SetReadBuffer(tr.Config.SockBuf); err != nil {
		fmt.Printf("SetReadBuffer: %+v\n", err)
	}
	if err := kcpconn.SetWriteBuffer(tr.Config.SockBuf); err != nil {
		fmt.Printf("SetWriteBuffer: %+v\n", err)
	}

	// stream multiplex
	var session *smux.Session
	if tr.Config.NoComp {
		session, err = smux.Client(kcpconn, tr.smuxConfig)
	} else {
		session, err = smux.Client(newCompStream(kcpconn), tr.smuxConfig)
	}
	if err != nil {
		return nil, errors.Wrap(err, "createConn()")
	}



	//fmt.Println("[INFO] createConn connected to ", kcpconn.RemoteAddr())
	return session, nil
}

// Waits until a connection has been established with remote peer
func (tr *ShadowTransport) waitConn() (*smux.Session) {
	//fmt.Println("[DEBUG] waitConn called")
	retry := 0
	for {
		//fmt.Println("[DEBUG] createConn called")
		if session, err := tr.createConn(); err == nil {
			//fmt.Println("[DEBUG] createConn succeeded")
			return session
		} else {
			//fmt.Println("[DEBUG] createConn failed")
			// TODO: Should we abort if we can't connect?
			retry++
			if retry > 10 {
				fmt.Println("[ERROR] Failed to connect to remote ShadowServer. Giving up.")
				break
			}
			time.Sleep(time.Second)
			fmt.Println("[DEBUG] Re-connecting:", err)
		}
	}
	return nil
}


func (st *ShadowTransport) RecordBorrowed(bytes uint64) {
	if st != nil {
		st.Password.mu.Lock()
		defer st.Password.mu.Unlock()

		// Doesn't work on BananaPi. Consider testing on EspressoBin.
		//atomic.AddUint64(&(st.Password.Borrowed), bytes)
		st.Password.Borrowed += bytes

		// If borrowed exceeds 95% of allocated bandwidth, then deactivate the transport.
		if st.Password.Borrowed > (st.Password.AllocatedBytes * 95 / 100) {
			//fmt.Println("[DEBUG] RecordBorrowed. AllocatedBytes", st.Password.AllocatedBytes, "Borrowed", st.Password.Borrowed)
			//st.Available = false
			st.RecordFailedConnection(ErrorExceededBandwidth)
		}

	}
}

// Encodes the original destination so that the remote peer knows who to forward the request to.
func RawAddr(addr string) (buf []byte, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ShadowNetwork: invalid address error %s %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("ShadowNetwork: invalid port %s", addr)
	}

	hostLen := len(host)
	l := 1 + 1 + hostLen + 2 // addrType + lenByte + address + port
	buf = make([]byte, l)
	buf[0] = 3             // 3 means the address is domain name
	buf[1] = byte(hostLen) // host address length  followed by host address
	copy(buf[2:], host)
	binary.BigEndian.PutUint16(buf[2+hostLen:2+hostLen+2], uint16(port))
	return
}

// Gets a free UDP port
func getFreePort() (int, error) {
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port, nil
}




// KCPTransport is an implementation of RoundTripper that supports HTTP,
// HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT) over a KCP Session.
// Most code is adapted from the standard Go 1.9 transport.go class with unneeded
// functionality removed.
//
// By default, KCPTransport caches connections for future re-use *by the same session*.
// Callers are responsible for ensure that transports are not shared by different sessions.
// If this is violated, then connections will not have the proper KCP credentials and calls
// will return with EOF or broken pipe errors.
//
// Transport uses HTTP/1.1 for HTTP URLs and either HTTP/1.1 or HTTP/2
// for HTTPS URLs, depending on whether the server supports HTTP/2,
// and how the Transport is configured. The DefaultTransport supports HTTP/2.
// To explicitly enable HTTP/2 on a transport, use golang.org/x/net/http2
// and call ConfigureTransport. See the package docs for more about HTTP/2.
type KCPTransport struct {
	PrivateTransport	*ShadowTransport 	// Reference to parent ShadowTransport.

	idleMu     sync.Mutex
	wantIdle   bool                                // user has requested to close all idle conns
	idleConn   map[connectMethodKey][]*persistConn // most recently used at end
	idleConnCh map[connectMethodKey]chan *persistConn
	idleLRU    connLRU

	reqMu       sync.Mutex
	reqCanceler map[*http.Request]func(error)

	altMu    sync.Mutex   // guards changing altProto only
	altProto atomic.Value // of nil or map[string]RoundTripper, key is URI scheme

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	//
	// The proxy type is determined by the URL scheme. "http"
	// and "socks5" are supported. If the scheme is empty,
	// "http" is assumed.
	//
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If DialContext is nil (and the deprecated Dial below is also nil),
	// then the transport dials using package net.
	//DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Dial specifies the dial function for creating unencrypted TCP connections.
	//
	// Deprecated: Use DialContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialContext takes priority.
	Dial func(network, addr string) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// If DialTLS is nil, Dial and TLSClientConfig are used.
	//
	// If DialTLS is set, the Dial hook is not used for HTTPS
	// requests and the TLSClientConfig and TLSHandshakeTimeout
	// are ignored. The returned net.Conn is assumed to already be
	// past the TLS handshake.
	DialTLS func(network, addr string) (net.Conn, error)


	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// If nil, the default configuration is used.
	// If non-nil, HTTP/2 support may not be enabled by default.
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives, if true, prevents re-use of TCP connections
	// between different HTTP requests.
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections across all hosts. Zero means no limit.
	MaxIdleConns int

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) connections to keep per-host. If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout, if non-zero, specifies the amount of
	// time to wait for a server's first response headers after fully
	// writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and
	// causes the body to be sent immediately, without
	// waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration

	// TLSNextProto specifies how the Transport switches to an
	// alternate protocol (such as HTTP/2) after a TLS NPN/ALPN
	// protocol negotiation. If Transport dials an TLS connection
	// with a non-empty protocol name and TLSNextProto contains a
	// map entry for that key (such as "h2"), then the func is
	// called with the request's authority (such as "example.com"
	// or "example.com:1234") and the TLS connection. The function
	// must return a RoundTripper that then handles the request.
	// If TLSNextProto is not nil, HTTP/2 support is not enabled
	// automatically.
	TLSNextProto map[string]func(authority string, c *tls.Conn) http.RoundTripper

	// ProxyConnectHeader optionally specifies headers to send to
	// proxies during CONNECT requests.
	ProxyConnectHeader http.Header

	// MaxResponseHeaderBytes specifies a limit on how many
	// response bytes are allowed in the server's response
	// header.
	//
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// nextProtoOnce guards initialization of TLSNextProto and
	// h2transport (via onceSetNextProtoDefaults)
	nextProtoOnce sync.Once
	//h2transport   *http2Transport // non-nil if http2 wired up

	// TODO: tunable on max per-host TCP dials in flight (Issue 13957)

}

// RoundTrip attempts to complete an http request through private network. Will retry on certain errors if they are
// likely to be temporary. If the request can't be fulfilled, will failover to local transport but will send back
// error to caller via context.
func (t *KCPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Add tracing to a specific domain. This can be helpful in debugging connection issues.
	//if strings.Contains(req.URL.String(), "restaurants") {
	//	fmt.Println("[DEBUG] RoundTrip() - Target Request", req.URL.String())
	//
	//	// Suppress gzip
	//	//req.Header.Set("Accept-Encoding", "identity")
	//	trace := &httptrace.ClientTrace{
	//		// A private network request does not currently trigger DNS lookups because these
	//		// are resolved by the server.
	//		//DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
	//		//	fmt.Printf("DNS Info: %+v\n", dnsInfo)
	//		//},
	//		GotConn: func(connInfo httptrace.GotConnInfo) {
	//			fmt.Printf("Got Conn: %+v\n", connInfo)
	//		},
	//	}
	//	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	//}

	// RoundTrip may be called multiple times in the event of a retry. We need to reset the
	// error message so we don't incorrectly report a public/local transport when in fact we
	// correctly got a private one.
	// Let the caller know that connection failed.
	ctx := req.Context()
	errormsg := ctx.Value(ShadowTransportFailed)
	if errormsg != nil {
		msgstruct := errormsg.(*ShadowNetworkFailure)
		msgstruct.Failed = false
	}

	//fmt.Printf("\n\n[DEBUG] Starting ShadowTransport RoundTrip(): %+v\n", req.URL)
	resp, err := t.roundTrip(req)
	//fmt.Printf("\n\n[DEBUG] ShadowTransport RoundTrip() returned: %+v  err=%v\n", req.URL, err)

	//if strings.Contains(req.URL.String(), "restaurants") {
	//
	//	if err == nil {
	//		fmt.Printf("\n\n[DEBUG] ShadowTransport RoundTrip() was private: %+v  err=%v\n", req.URL)
	//	} else {
	//		fmt.Printf("\n\n[DEBUG] ShadowTransport RoundTrip() was not private: %+v  err=%v\n", req.URL, err)
	//	}

	//
	//	// Dump the request
	//	dump, _ := httputil.DumpRequestOut(req, true)
	//	fmt.Printf("Request Dump: %+v\n\n", string(dump))
	//
	//	// Dump the body - this will prevent the request from completing
	//	body, _ := ioutil.ReadAll(resp.Body)
	//	fmt.Printf("[DEBUG] Target body (len=%d): \n%s\n", len(body), string(body))
	//}

	if err != nil {
		// Note: "context canceled" means the user closed their browser or otherwise cancelled the request.
		if t.PrivateTransport.network.Logger != nil {
			t.PrivateTransport.network.Logger.Error("RoundTrip()", "Error", "Falling back to local transport", "Addr", req.URL.Hostname(), "Time", time.Since(start), "Err", err, "Local", t.PrivateTransport.network.Name[0:10],"Remote", t.PrivateTransport.ID[0:10])
		}
	} else {
		if t.PrivateTransport.network.Logger != nil {
			t.PrivateTransport.network.Logger.Info("RoundTrip()", "Status", "Success", "Addr", req.URL.Hostname(), "Time", time.Since(start), "Local", t.PrivateTransport.network.Name[0:10],"Remote", t.PrivateTransport.ID[0:10])
		}
	}

	// We received a valid response from the server so reset connection errors
	if err == nil {
		t.PrivateTransport.ConnectionErrors = 0
	} else {
		// Bad peer detection
		// Keep track of successive response errors from remote peers so we can deactivate them.
		// POST requests often do not return responses, so ignore these.
		if t.PrivateTransport != nil {
			ignore := false
			//if strings.Contains(err.Error(), "i/o timeout") && req.Method == "POST" {
			if req.Method == "POST" {
				ignore = true
			}

			if !ignore  {
				//elapsed := time.Since(start)

				// Uncommment to see P2P errors.
				//fmt.Printf("[ERROR] P2P error in RoundTrip() [%s] [%s] %+v\n", req.URL, t.PrivateTransport.RemoteIP, err.Error())

				// Record the error
				if strings.Contains(err.Error(), "broken pipe") {
					t.PrivateTransport.RecordFailedConnection(ErrorConnectionFailed)
				} else {
					t.PrivateTransport.RecordFailedConnection(err.Error())
				}
			}
		}

		// Fall back to local transport.
		//fmt.Println("[DEBUG] Couldn't connect to remote peer. Falling back to local transport.")

		// Let the caller know that connection failed.
		ctx := req.Context()
		errormsg := ctx.Value(ShadowTransportFailed)
		if errormsg != nil {
			msgstruct := errormsg.(*ShadowNetworkFailure)
			msgstruct.Failed = true
		}

		// DEBUGGING - makes P2P errors easier to debug by not failing over to local network
		//if strings.Contains(req.URL.String(), "facebook.com") {
		//	return nil, err
		//}

		localtransport := t.PrivateTransport.network.DefaultTransport
		//start := time.Now()
		resp, err = localtransport.RoundTrip(req)

		//if strings.Contains(req.URL.String(), "push.aha.io") {
		//	if err != nil {
		//		fmt.Printf("[ERROR] Error detected from local RoundTrip: %s\n%+v\n", req.URL.String(), err.Error())
		//		fmt.Println()
		//	} else {
		//		fmt.Printf("[DEBUG] Local RoundTrip (failover) success: %s\n\n", req.URL.String())
		//	}
		//}

		//elapsed := time.Since(start)
		//fmt.Printf("[INFO] RoundTrip 3 took %s\n", elapsed)
		//fmt.Printf("[DEBUG] Results from local transport. Err=%+v  Resp=%+v\n", err, resp)

	}

	//fmt.Printf("\n\n[DEBUG] ShadowTransport RoundTrip() completed: %+v\n", err)

	return resp, err
}

func (t *KCPTransport) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {

	// Make sure we can see the original ShadowTransport and get its cipher
	tr := ctx.Value(ShadowTransportKey)

	if (tr == nil) {
		//fmt.Printf("[ERROR] ShadowTransport was not included in Request context.\n")
		return nil, errors.New("ShadowTransport:DialContext() ShadowTransport was not included in Request context")
	}

	// Convert interface to ShadowTransport so we can get the cipher
	st := tr.(*ShadowTransport)

	sn := st.network

	// If the transport went dead or the domain is internal, then resolve with a local transport
	// RLS 11/30/2018 - Removed call to isExternal. We do not call blacklisted domains and local resources
	// have to be identified by IP address anyway.
	// || !st.AllowInternalRequests && !isExternal(addr)
	if !st.IsAvailable() {
		//fmt.Printf("[DEBUG] Dialcontext [%s]- st.IsAvailable(): %t  isExternal(): %t\n", addr, st.IsAvailable(), isExternal(addr))
		// The transport failed so we need to let callers know
		if !st.Available {
			//sn.mu.Lock()
			//defer sn.mu.Unlock()
			//sn.PrivateTransport[st.ID] = st
			//fmt.Printf("  *** Private transport connect attempt failed. Deactivating node. %v\n", n.ID)

			// Modify the failure key to the ctx so the caller can tell we failed.
			errormsg := ctx.Value(ShadowTransportFailed)
			if errormsg != nil {
				msgstruct := errormsg.(*ShadowNetworkFailure)
				msgstruct.Failed = true
			}
		}

		// Logging
		if sn.Logger != nil {
			if !st.Available {
				sn.Logger.Warn("ShadowTransport.DialContext()", "Error", "Private transport was unavailable. Using local transport.", "Local", sn.Name[0:10],"Remote", st.ID[0:10])
			} else {
				sn.Logger.Warn("ShadowTransport.DialContext()", "Error", "Using local transport for internal IP address.", "Local", sn.Name[0:10],"Remote", st.ID[0:10])
			}
		}

		conn, err := net.Dial(network, addr)

		/*if err != nil {
			fmt.Printf("  *** dialcontext 1 error = %+v\n", err)
		}*/
		return conn, err
	}

	// Get an available session
	idx := st.rr % uint16(st.Config.Conn)
	st.rr++

	deactivate := false

	// do auto expiration && reconnection
	var err error
	st.mu.Lock()
	if st.Renegotiate || st.muxes[idx].session.IsClosed() || (st.Config.AutoExpire > 0 && time.Now().After(st.muxes[idx].ttl)) {
		if sn.Logger != nil {
			sn.Logger.Info("ShadowTransport:DialContext()", "msg", "Restarting Mux", "Local", sn.Name[0:10], "Remote", st.ID[0:10])
		}

		// TODO: Possible race condition? Scavenging happens once per second. Is muxes[idx] guaranteed to be available then?
		st.Renegotiate = false
		//fmt.Printf("[DEBUG] Sending session to scavenger\n")
		// Tell the scavenger to monitor this session
		st.chScavenger <- st.muxes[idx].session
		//fmt.Printf("[DEBUG] Waiting for new connection\n")
		st.muxes[idx].session = st.waitConn()
		//fmt.Printf("[DEBUG] Received new connection\n")
		if st.muxes[idx].session == nil {
			if sn.Logger != nil {
				sn.Logger.Error("ShadowTransport:DialContext()", "msg", "Remote Mux couldn't be restarted. Deactivating.", "Error", err, "Local", sn.Name[0:10],"Remote", st.ID[0:10])
			}
			deactivate = true
		}

		if sn.Logger != nil {
			sn.Logger.Info("ShadowTransport:DialContext()", "msg", "Mux successfully restarted", "Local", sn.Name[0:10], "Remote", st.ID[0:10])
		}
	}
	st.mu.Unlock()

	var conn *smux.Stream
	if !deactivate {
		sess := st.muxes[idx].session

		if sn.Logger != nil {
			sn.Logger.Info("ShadowTransport:DialContext()", "msg", "Opened stream", "Local", sn.Name[0:10], "Remote", st.ID[0:10])
		}

		// TODO: Re-use streams. This will enable keep-alive requests and prevent clients expecting
		// keep-alive connections from getting EOF errors.
		conn, err = sess.OpenStream()

		if err != nil {
			deactivate = true
		}

		// Parse the forwarding address
		rawAddr, err := RawAddr(addr)
		if (err != nil) {
			//fmt.Printf("[ERROR] DialContext() - RawAddr failed. Aborting connection request.\n")
			return nil, err
		}

		// Set an idle timeout on the stream. This will close the stream if nothing is read or written to
		// it within this period of time.
		conn.SetIdleTimeout(time.Duration(connectionIdleTimeout) * time.Second)

		// Write the forwarding address to the stream
		if _, err = conn.Write(rawAddr); err != nil {
			if sn.Logger != nil {
				sn.Logger.Error("ShadowTransport:DialContext()", "Couldn't write destination to private stream. Closing stream.", "Error", err, "Local", sn.Name[0:10],"Remote", st.ID[0:10])
			}
			conn.Close()
			deactivate = true
		}
	}
	// It's unlikely this will ever be called because all of the above functions are broadcast only
	if deactivate {
		// If transport fails, deactivate it and fall back to non-private conn.
		fmt.Printf("[ERROR] ShadowTransport:DialContext() - Private network connection failed. Falling back to local connection. err: %+v\n", err)
		var d net.Dialer
		if ctx == nil {
			ctx = context.Background()
		}
		conn, err := d.DialContext(ctx, network, addr)

		if sn.Logger != nil {
			sn.Logger.Error("ShadowTransport:DialContext()", "Connect attempt failed. Deactivating private transport.", "Local", sn.Name[0:10],"Remote", st.ID[0:10])
		}

		st.RecordFailedConnection(ErrorConnectionFailed)
		//st.Available = false
		sn.mu.Lock()
		defer sn.mu.Unlock()
		sn.PrivateTransport[st.ID] = st
		//fmt.Printf("  *** Private transport connect attempt failed. Deactivating node. %v\n", n.ID)

		// Modify the failure key to the ctx so the caller can tell we failed.
		errormsg := ctx.Value(ShadowTransportFailed)
		if errormsg != nil {
			msgstruct := errormsg.(*ShadowNetworkFailure)
			msgstruct.Failed = true
		}

		return conn, err

	}

	//fmt.Println("[DEBUG] DialContext() - established net.conn to remote peer")
	// Unit tests use this. Remove at your own risk.
	if sn.Logger != nil {
		sn.Logger.Info("ShadowTransport:DialContext()", "Connected to peer shadowServer stream", "", "Addr", addr, "Local", sn.Name[0:10],"Remote", st.ID[0:10])
	}

	return conn, err

}


/*
func (t *KCPTransport) PrintAddr(log string) {
	fmt.Printf("[DEBUG] KCPTransport address [%s] %p\n", log, t)
}*/

// Pings the remote peer for a verification message. This allows us to tell if the peer is responsive on port 7777
// as well as if it has internet connectivity
// id is the peer node of the caller. Used for debugging.
// Returns: Responsive, HasInternet (bool)
var VerifyPeerTimeout = time.Duration(4) * time.Second
func (t *ShadowTransport) VerifyPeer(id string) (bool, bool) {
	//if t.ID[0] == '1' {
	//	fmt.Printf("[DEBUG] [%s] VerifyPeer(%s) \n", id[0:10], t.ID[0:10])
	//}
	// Don't write - can't hold lock
	//t.LastVerification = time.Now().Local()

	requestcontext := context.WithValue(context.Background(), ShadowTransportKey, t)
	conn, err := t.Transport.(*KCPTransport).DialContext(requestcontext, "tcp", "verify.winstonprivacy.com:80")
	if err != nil {
		return false, false
	}

	// Only you can prevent connection leaks!
	defer conn.Close()

	// Make the request
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")

	// Wait for response. This could block so we wrap the reader in a goroutine and use channels to timeout.
	reader := bufio.NewReader(conn)
	s := make(chan string)
	e := make(chan error)
	go func() {
		status, err := reader.ReadString('\n')
		if err != nil {
			e <- err
		} else {
			s <- status
		}
		close(s)
		close(e)
	}()

	var status string
	select {
	case line := <- s:
		status = line
	case err := <- e:
		if t.network.Logger != nil {
			t.network.Logger.Error("VerifyPeer()", "Error", err, "Local", t.network.Name[0:10],"Remote", t.ID[0:10])
		}
		return false, false
	case <- time.After(VerifyPeerTimeout):
		if t.network.Logger != nil {
			t.network.Logger.Error("VerifyPeer()", "Error", "Timeout 1", "Local", t.network.Name[0:10],"Remote", t.ID[0:10])
		}

		return false, false
	}

	if !strings.Contains(status, "200 OK") {
		if t.network.Logger != nil {
			t.network.Logger.Error("VerifyPeer()", "Error", "Bad Status Code" + status, "Local", t.network.Name[0:10],"Remote", t.ID[0:10])
		}
		return false, false
	}

	// We should receive a second line with the connectivity status
	s2 := make(chan string)
	e2 := make(chan error)
	go func() {
		connectionstatus, err := reader.ReadString('\n')
		if err != nil {
			e2 <- err
		} else {
			s2 <- connectionstatus
		}
		close(s2)
		close(e2)
	}()
	var connectionstatus string
	select {
	case line := <- s2:
		//fmt.Printf("[DEBUG] [%s] VerifyPeer() Received connectionstatus 2 - %s\n", t.ID[0:10], line)
		connectionstatus = line
	case err := <- e2:
		if t.network.Logger != nil {
			t.network.Logger.Error("VerifyPeer()", "Error 2", err, "Local", t.network.Name[0:10],"Remote", t.ID[0:10])
		}
		return true, false
	case <- time.After(VerifyPeerTimeout):
		if t.network.Logger != nil {
			t.network.Logger.Error("VerifyPeer()", "Error 2", "Timeout", "Local", t.network.Name[0:10],"Remote", t.ID[0:10])
		}
		return true, false
	}

	if strings.HasPrefix(connectionstatus, "Status") && strings.Contains(connectionstatus, "true") {
		return true, true
	}

	return true, false
}