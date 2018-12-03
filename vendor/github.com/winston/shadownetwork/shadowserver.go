/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, March 2018
*/

/* Implementation of a fast Shadowsocks server. This is intended to run in the background
 * and service remote http/s requests from other Winston peers.
 * TODO: Add connection throttling?
 */


package shadownetwork

import (
	"errors"
	"runtime"
	"fmt"
	//"sync"
	"os"
	//"io/ioutil"
	"log"
	"strconv"
	//"syscall"
	"net"
	"io"
	"encoding/binary"
	//"strings"
	"sync/atomic"
	"time"
	"net/http"
	"crypto/tls"
	"context"
	"github.com/winstonprivacyinc/dns"
	kcp "github.com/winstonprivacyinc/kcp-go"
	"github.com/winstonprivacyinc/smux"
	"github.com/golang/snappy"
	"crypto/sha1"
	"golang.org/x/crypto/pbkdf2"
	"sync"
	//"bytes"
	"strings"
	//"bufio"
)

const logCntDelta = 100

var connCnt int
var nextLogConnCnt int = logCntDelta

// Password salt
const salt = "winston1"


const clientReadTimeout = 30	// Client request timeout in seconds
const serverReadTimeout = 600	// Streams will never stay open longer than this period of time. Should match password expiration time.
const serverDialTimeout = 10	// Server connection timeout in seconds
const connectionIdleTimeout = 60 	// Connection will be dropped if no activity in this period of time.

type ShadowServer struct {
     // Important: Fields which require atomic access must be declared first in the structure to ensure that they are aligned properly.
     // https://stackoverflow.com/questions/28670232/atomic-addint64-causes-invalid-memory-address-or-nil-pointer-dereference
	NumRequests   			uint64         		// records # of requests. Use only for unit testing.

	password      			string
	cipher        			*kcp.BlockCrypt		// Current cipher. This has to be set to nil to force a password change.
	network       			*ShadowNetwork 		// pointer to the parent ShadowNetwork
	Debug         			bool           		// if true, will output debug info to stdout
	CurrentPasswordStarttime	time.Time      		// When the current password was reset. Used to meter bandwidth to requestors.
	Meter				func(int, net.Addr)	// Optional callback to record how many bytes were consumed by clients
	Transport 			*http.Transport		// The transport to use when dialing outbound connections. Used for custom DNS resolution.
	Config				*ShadowServerConfig	// Contains low level kcptun settings
	muxes 				[]*smux.Session		// active inbound sessions
	passwordmu			sync.RWMutex		// Protects the password generation routine
	Listener			*kcp.Listener		// Reference to the currently active listener. Only one listener may be active at a time.

	isClosed			bool			// Set to true if the listener is closed. Allows sessions to abort.
	closemu				sync.RWMutex		// Protects isClosed

	listenlock			sync.RWMutex		// Ensures only one listener can run at a time.
	Addr, Port			string			// Address and port of shadow server listener
	ignorePeerCheck			bool			// Ignore peer validity checks. Used for unit testing.
	IdleTimeout			int			// Optional: Idle connections will close in this period of time.
	MaxTimeout			int			// Optional: Streams will close after this period of time, even if active.

	// Attach a resolver function to this to spoof DNS. Used only for unit testing.
	DNSIPResolver			func(host string) (string)
}

type ShadowServerConfig struct {
	//Listen       string `json:"listen"`
	//Target       string `json:"target"`
	//Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	KeepAlive    int    `json:"keepalive"`
	Log          string `json:"log"`
	//SnmpLog      string `json:"snmplog"`
	//SnmpPeriod   int    `json:"snmpperiod"`
	//Pprof        bool   `json:"pprof"`
	Quiet        bool   `json:"quiet"`

	// Client-only Settings
	AutoExpire   int    `json:"autoexpire"`
	ScavengeTTL  int    `json:"scavengettl"`
	Conn         int    `json:"conn"`		// Number of simultaneous connections to remote peer
}


// Shuts down the server
func (server *ShadowServer) Close() {
	server.closemu.Lock()
	defer server.closemu.Unlock()

	if server.Listener != nil && !server.Listener.IsClosed() {
		server.Listener.Close()
	}
	server.isClosed = true

}

// Callback should be the passed the ShadowNetwork's CurrentPassword() func. If nil, we won't enforce password
// expiration for each incoming password and will just let ShadowNetwork take care of it (with a possible delay).
// If outputdebug is set, will output debug information to stderr and count the # of requests. Don't use in production.
// Addr is optional. If blank, will listen on 127.0.0.1:[port].
func StartShadowServer(addr string, port string, password string, parentnetwork *ShadowNetwork, outputdebug bool, useLocalDNSOnly bool) (*ShadowServer, error) {

	server := ShadowServer {
		//passwdManager: PasswdManager{portListener: map[string]*PortListener{}},
		password:   	password,
		network: 	parentnetwork,
		Debug:		outputdebug,
		CurrentPasswordStarttime:	time.Now().Local(),
		Config: 	GetServerConfig(),
		Addr:		addr,
		Port:		port,
		IdleTimeout: 	connectionIdleTimeout,					// User can override.
		MaxTimeout: 	serverReadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,				// Doesn't check authenticity of downstream certs. Client should do this.
				MinVersion:         tls.VersionTLS11,			// TEST
				MaxVersion:         tls.VersionTLS12,			// TEST
				Renegotiation:      tls.RenegotiateFreelyAsClient,	// TEST
			},

		},
	}

	if !useLocalDNSOnly {
		//fmt.Println("[INFO] Using DNS on port 53 and port 54")
		server.Transport.DialContext = HijackDNS()
	} else {
		//fmt.Println("[INFO] Using DNS on port 53 only")
		server.Transport.DialContext = (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
			DualStack: true,
		}).DialContext
	}

	portnum, err := strconv.Atoi(port)

	if err != nil || portnum < 1000 || portnum > 65535 || len(password) == 0 {
		return nil, errors.New("Must supply port (1000-65535) and password to initialize shadow server.")
	}

	// Use two cores to service requests
	runtime.GOMAXPROCS(2)

	// Kick off a listener. This will run until the password is changed.
	go server.listen()
	return &server, nil
}

func (server *ShadowServer) ChangePassword(password string, skipduplicatepasswordcheck bool) {
	if len(password) == 0 || server==nil {
		return
	}

	server.passwordmu.Lock()
	defer server.passwordmu.Unlock()

	// Make sure we don't try to change the password to itself. This can happen because both ShadowNetwork
	// and ShadowServer can call this function.
	if !skipduplicatepasswordcheck && password == server.password {
		return
	}

	// Close all open sessions. They have to be renegotiated by peers on password changes.
	//fmt.Println("[DEBUG] ShadowServer.ChangePassword() - Shadowserver closing all inbound sessions")
	for _, v := range server.muxes {
		v.Close()
	}
	// Clear the active sessions slice
	server.muxes = nil

	server.CurrentPasswordStarttime = time.Now().Local()
	server.password = password
	server.cipher = nil

	// Update allocated bytes for all connected peers
	server.network.ComputeBandwidthAllocation()

	// Reset recent contributions
	server.network.PeerStore.ResetRecentContributions()

	// Change the cipher after the sessions have closed
	newblock := server.generateBlock(server.password, server.Config.Crypt)
	//fmt.Println("[DEBUG] server", server)
	//fmt.Println("[DEBUG] newblock", newblock, "password", server.password, "crypt", server.Config.Crypt)
	//fmt.Println("[DEBUG] server.Listener", server.Listener)
	server.cipher = newblock

	if server.Listener != nil {
		server.Listener.UpdateBlock(newblock)
	}

	//fmt.Println("[DEBUG] ShadowServer.ChangePassword completed password change to", password)
}

// Converts a plaintext password to a ciphered block
func (server *ShadowServer) generateBlock(password string, encryption string) (*kcp.BlockCrypt) {




	pass := pbkdf2.Key([]byte(password), []byte(salt), 4096, 32, sha1.New)
	var block kcp.BlockCrypt
	switch encryption {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		server.Config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}
	return &block

}

func checkError(err error) {
	if err != nil {
		log.Printf("[ERROR] %+v\n", err)
		//os.Exit(-1)
	}
}

// Starts a shadowserver listener. Only one listener may be active at a time so the caller is responsible
// for closing any existing listener and setting the Listener property to nil.
// If Addr is not provided, will listen for incoming UDP packets on all interfaces at specified port.
func (server *ShadowServer) listen() {
	if server.Port == "" {
		fmt.Printf("[ERROR] ShadowServer.Listen() - ShadowServer port must be specified.")
		return
	}

	server.listenlock.Lock()
	defer server.listenlock.Unlock()

	if server.network.Logger != nil {
		server.network.Logger.Info("ShadowServer.Listen()", "msg", " Launching shadow privacy service", "addr", server.Addr + ":" + server.Port)
	}

	//fmt.Printf("[INFO] ShadowServer.Listen() - Launching shadow privacy service on local address %s with password: %s\n", server.Addr + ":" + server.Port, server.password)

	server.passwordmu.Lock()
	server.cipher = server.generateBlock(server.password, server.Config.Crypt)
	server.passwordmu.Unlock()

	// Creates a listener
	var err error
	//fmt.Printf("[DEBUG] ShadowServer - Starting KCP listener at %s\n", server.Addr + ":" + server.Port)
	server.Listener, err = kcp.ListenWithOptions(server.Addr + ":" + server.Port, *server.cipher, server.Config.DataShard, server.Config.ParityShard)
	checkError(err)

	if err := server.Listener.SetDSCP(server.Config.DSCP); err != nil {
		log.Println("[ERROR] SetDSCP:", err)
	}
	if err := server.Listener.SetReadBuffer(server.Config.SockBuf); err != nil {
		log.Println("[ERROR] SetReadBuffer:", err)
	}
	if err := server.Listener.SetWriteBuffer(server.Config.SockBuf); err != nil {
		log.Println("[ERROR] SetWriteBuffer:", err)
	}

	for {
		// Abort the listener if the pipe has closed.
		server.closemu.RLock()
		closed := server.Listener.IsClosed()
		server.closemu.RUnlock()
		if closed {
			break
		}
		// Hang out here until we get a stream request.
		// The timeout allows us to fail faster if bad ciphers are sent. This is typical if
		// we unexpectedly restart and changed our password.
		server.Listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if conn, err := server.Listener.AcceptKCP(); err == nil {
			if server.network.Logger != nil {
				server.network.Logger.Info("ShadowServer.Listen()", "msg", "Received incoming request for mux.", "Local", server.network.Name[0:10])
			}

			// Start new Mux
			conn.SetStreamMode(true)
			conn.SetWriteDelay(true)
			conn.SetNoDelay(server.Config.NoDelay, server.Config.Interval, server.Config.Resend, server.Config.NoCongestion)
			conn.SetMtu(server.Config.MTU)
			conn.SetWindowSize(server.Config.SndWnd, server.Config.RcvWnd)
			conn.SetACKNoDelay(server.Config.AckNodelay)

			if server.Config.NoComp {
				go server.handleMux(conn, false)
			} else {
				go server.handleMux(newCompStream(conn), true)
			}

		} else {
			if server.network.Logger != nil && !strings.Contains(err.Error(), "i/o timeout") {
				server.network.Logger.Info("ShadowServer.Listen()", "msg", "Couldn't open ShadowServer smux", "err", err.Error(), "Local", server.network.Name[0:10])
			}

		}

	}

	//fmt.Printf("[DEBUG] [%s] ShadowServer.Listen() - Closing ShadowServer on %s.\n", server.network.Name[0:10], server.Addr + ":" + server.Port)
}

// Used for logging
var openmuxes int64
var openstreams int64
var nextlogtime time.Time

// stream multiplexer. A mux processes multiple requests/streams from a given remote peer.
// Will respond to valid ping and verification requests. Peers must be verified before ordinary web requests will be returned.
func (server *ShadowServer) handleMux(conn io.ReadWriteCloser, compressed bool) {
	peerverified := false
	atomic.AddInt64(&openmuxes, 1)
	//openmuxes++
	defer func() {
		atomic.AddInt64(&openmuxes, -1)
		//openmuxes--
	}()

	if server.network.Logger != nil  {
		server.network.Logger.Info("ShadowServer.handleMux()", "Opening new Mux.", "", "Local", server.network.Name[0:10])
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = server.Config.SockBuf
	smuxConfig.KeepAliveInterval = time.Duration(server.Config.KeepAlive) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		if server.network.Logger != nil  {
			server.network.Logger.Info("ShadowServer.handleMux()", "Failed to open new Mux. Error.", err, "Local", server.network.Name[0:10])
		}
		return
	}

	// ChangePassword closes all muxes and removes them from this slice every 10 minutes.
	server.muxes = append(server.muxes, mux)

	defer mux.Close()
	//defer conn.Close()

	var peer *ShadowPeer
	// Request handler loop
	for {
		var client *smux.Stream
		validstream := false
		// Hang out here until we close the session or we get a valid request
		//fmt.Printf("[DEBUG] AcceptStream() - waiting for stream request\n")
		for {
			server.closemu.RLock()
			closed := server.isClosed
			server.closemu.RUnlock()
			if closed {
				break
			}
			//fmt.Printf("[DEBUG] AcceptStream()...\n")
			// Set deadline. This ensures that callers who send a bad password/cipher will timeout more quickly.
			mux.SetDeadline(time.Now().Add(500 * time.Millisecond))
			client, err = mux.AcceptStream()
			if err==nil && client!=nil {
				validstream = true
				break
			}
			if !strings.Contains(err.Error(), "i/o timeout") {
				// broken pipe (cipher change) - we close down the mux handler. There's no way to recover it
				// so we have to abort.
				//fmt.Printf("[DEBUG] handlemux 2() err=%v\n", err)
				return
			}

		}
		//fmt.Printf("[DEBUG] AcceptStream() - Accepted a new stream/request... err: %v\n", err)
		// Note: if the session is broken, a "broken pipe" will occur here even if a request hasn't come in
		if validstream {
			// Check to ensure peer is valid. This only needs to be done once per mux.
			if !peerverified {
				if server.ignorePeerCheck {
					// Make a dummy peer for unit testing
					peer = &ShadowPeer{
						ID: "DummyPeerForUnitTesting",
						Contribution: make(map[string]uint64),
						maxBandwidthBytesPerSec: 1000000,
						AllocatedBytes: 100000000,
					}
				} else {
					// cast to correct type and get peer. If we haven't connected with the
					// remote peer, then we won't have a peer.


					if compressed {
						//fmt.Println("[DEBUG] GetShadowPeer 1 - peer", peer, "peer store", server.network.PeerStore)
						peerkey := conn.(*compStream).RemoteAddr()
						//fmt.Println("[DEBUG] Looking for key:", peerkey)
						peer = server.network.GetShadowPeerByIP(peerkey)
						//fmt.Println()
						//fmt.Printf("[DEBUG] peer.UpdateContribution=%v  stream=%p  stream.conn=%p\n", peer.UpdateContribution, conn.(*compStream), &(conn.(*compStream).conn))
						conn.(*compStream).WriteMeter = peer.UpdateContribution

						//fmt.Println("[DEBUG] GetShadowPeer 2 - peer", peer, "peer store", server.network.PeerStore)
					} else {
						peerkey := conn.(*kcp.UDPSession).RemoteAddr()
						peer = server.network.GetShadowPeerByIP(peerkey)
						conn.(*kcp.UDPSession).WriteMeter = peer.UpdateContribution
					}
				}

				if peer != nil {
					peerverified = true
					peer.CurrentPasswordStart = server.CurrentPasswordStarttime

				}
			}

			remote := "unknownpeer"
			if peer != nil {
				remote = peer.ID[0:10]
			}

			if !peerverified {
				if server.network.Logger != nil {
					server.network.Logger.Warn("ShadowServer.Listen()", "msg", "Peer is not verified. Will only respond to ping and verify.", "Local", server.network.Name[0:10])
				}
			}

			// Process the request
			//fmt.Printf("[DEBUG] handlemux() - Processing request\n")
			go func(client *smux.Stream) {
				atomic.AddInt64(&openstreams, 1)
				//openstreams++
				defer func() {
					client.Close()
					atomic.AddInt64(&openstreams, -1)
					//openstreams--
				}()

				// Peer could equal nil here. This would happen if we received a request from a newly connected
				// peer that hasn't had a chance to get added to our private transport tables yet.
				// Bandwidth Check
				bandwidthexceeded := false
				if peer != nil && peer.BandwidthExceeded() {
					bandwidthexceeded = true
				}

				if server.Debug {
					// Used for unit testing. Don't remove.
					atomic.AddUint64(&(server.NumRequests), 1)
				}

				// Set read timeout on client
				client.SetReadDeadline(time.Now().Add(clientReadTimeout * time.Second))
				host, extra, err := getRequest(client)
				if err != nil {
					if server.network.Logger != nil {
						server.network.Logger.Error("ShadowServer.handleMux()", "Error parsing request. Dropping stream.", err, "Local", server.network.Name[0:10], "Remote", remote)
					}
					// TODO: Return bad request error
					return
				}

				if strings.HasPrefix(host, "ping.winstonprivacy.com") {
					// Ping can be used for measuring peer-peer latency.
					// Return a response to caller
					returnmsg := "HTTP/1.1 200 OK\r\nStatus: Ok\r\n"
					io.WriteString(client, returnmsg)

					if server.network.Logger != nil {
						server.network.Logger.Info("ShadowServer.handleMux()", "Ping", "Pong", "Local", server.network.Name[0:10], "Remote", remote)
					}
				} else if strings.HasPrefix(host, "verify.winstonprivacy.com") {
					// Test our own connectivity and return the results to the caller
					start := time.Now()
					// Attempt to connect to an external resource and if successful, return a status header
					// Ironically enough, we'll use Google for this because they should work everywhere.
					dnsbypassctx := context.Background()
					dnsbypassctx = context.WithValue(dnsbypassctx, dns.UpstreamKey, 0)
					dnsbypassctx, _ = context.WithTimeout(dnsbypassctx, 2 * time.Second)
					testserver, err := server.Transport.DialContext(dnsbypassctx, "tcp", "www.msftncsi.com:80")
					hasinternet := false
					if err == nil {
						hasinternet = true
						testserver.Close()
					} else {
						// Retry a second time to Google's servers if this fails.
						testserver, err := server.Transport.DialContext(dnsbypassctx, "tcp", "www.google.com:443")
						if err == nil {
							hasinternet = true
							testserver.Close()
						}
					}

					// If the peer receives a 200 OK, then they know we can relay requests for them
					// TODO: Is peer checking for 200 OK or Status?
					statusline := fmt.Sprintf("Status: %t", hasinternet)
					returnmsg := "HTTP/1.1 200 OK\r\n" + statusline + "\r\n"
					io.WriteString(client, returnmsg)

					if server.network.Logger != nil {
						server.network.Logger.Info("ShadowServer:handleMux()", "msg", "Received network verification Request", "Time", time.Since(start), "Local", server.network.Name[0:10], "Remote", remote)
					}

				} else if peerverified && !bandwidthexceeded {

					// Connect to remote site using the unblocked DNS (ie: do not filter remote queries via local blacklist)
					dnsbypassctx := context.Background()
					dnsbypassctx = context.WithValue(dnsbypassctx, dns.UpstreamKey, 0)

					// Add timeout on the initial dial. Per comments in dial.go, once successfully connected
					// expiration of the context will not affect the connection.
					dnsbypassctx, _ = context.WithTimeout(dnsbypassctx, serverDialTimeout * time.Second)

					if server.DNSIPResolver != nil {
						fmt.Println("[DEBUG] DNS to IP Hook triggered.")
						host = server.DNSIPResolver(host)
					}

					start := time.Now()
					backend, err := server.Transport.DialContext(dnsbypassctx, "tcp", host)

					if err != nil {
						if server.network.Logger != nil {
							server.network.Logger.Error("ShadowServer:handleMux()", "Error dialing host. Dropping stream.", err, "Local", server.network.Name[0:10], "Remote", remote)
						}
						// TODO: Return connection error
						return
					}
					defer backend.Close()

					// We probably consumed more bytes than the original destination site. Pipe these to the destination server
					// before proceeding.
					if extra != nil {
						if _, err = backend.Write(extra); err != nil {
							if server.network.Logger != nil {
								server.network.Logger.Error("ShadowServer:handleMux()", "Error writing extra data. Dropping stream.", err, "Local", server.network.Name[0:10], "Remote", remote)
							}
							return
						}
					}

					if server.network.Logger != nil {
						server.network.Logger.Info("ShadowServer:handleMux()", "msg", "Relay Request", "Addr", host, "Time", time.Since(start), "Local", server.network.Name[0:10], "Remote", remote)
					}

					// Pipe the content back to the client
					server.fuse(client, backend, host, start)

				} else {
					if bandwidthexceeded {
						if server.network.Logger != nil {
							server.network.Logger.Debug("ShadowServer:handleMux()", "Error", "Peer exceeded bandwidth. Ignoring request.", "Local", server.network.Name[0:10], "Remote", remote)
						}

						// TODO: Return back off error

					} else {
						if server.network.Logger != nil {
							server.network.Logger.Debug("ShadowServer.handleMux()", "Error", "Don't recognize peer. Ignoring request.", "Local", server.network.Name[0:10], "Remote", remote)
						}
						// TODO: Return authentication error
					}

				}

			}(client)

		}
	}

	if server.network.Logger != nil {
		server.network.Logger.Info("ShadowServer:handleMux()", "msg", "Closing Mux.", "Local", server.network.Name[0:10], "Remote", peer.ID[0:10])
	}

}

func getRequest(conn *smux.Stream) (host string, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip address start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
		lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
		lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 1024)
	var n int
	// read till we get possible domain length field
	// TODO: Send timeout in method params
	// Don't set this too short because it will cause the stream
	// to close. FIX for WINSTON-178.
	conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(10)))
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		//log.Print("error: %+v\n", err)
		if err == io.ErrShortBuffer {

		} else {
			return
		}
	}
	// Reset the deadline
	conn.SetReadDeadline(time.Time{})

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", buf[idType])
		return
	}

	if n < reqLen { // rare case
		var _n int
		if _n, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			if _n > 0 && err != io.ErrUnexpectedEOF {

			} else {
				return
			}
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

// Fuse connections together. Have to take precautions to close connections down in various cases.
// TODO: Check the bandwidth every 1Mb in handleClient to enforce bandwidth limits during large requests?
func (server *ShadowServer) fuse(client, backend net.Conn, host string, start time.Time) (time.Duration) {
	defer client.Close()
	defer backend.Close()

	var elapsed time.Duration
	//serverclosed := false
	// Pipes data from the remote server to our client
	backenddie := make(chan struct{})
	go func() {
		// Wrap the backend connection so that we can enforce an idle timeout.
		idleconn := &IdleTimeoutConn{Conn: backend, IdleTimeout: server.IdleTimeout}

		// Connections cannot stay open longer than this period of time.
		idleconn.SetDeadline(time.Now().Add(time.Duration(server.MaxTimeout) * time.Second))


		// DEBUG: To pipe the server response to stderr
		//fmt.Println("[DEBUG] Response follows:")
		//spyconnection := &SpyConnection{idleconn}
		//n, err := copyData(client, spyconnection)

		// This should be uncommented for production code
		n, err := copyData(client, idleconn)
		//fmt.Printf("[DEBUG] Response was %d bytes long\n", n)

		//if debug && err != nil {
		if err != nil && !strings.Contains(err.Error(), "closed network connection") {
			//fmt.Printf("fuse error backend->client: %d bytes transferred. Err=%s\n", n, err)
			if server.network.Logger != nil {
				server.network.Logger.Error("ShadowServer.Fuse()", "Error transferring from backend->client", err, "Addr", host, "Bytes", n, "Local", server.network.Name[0:10])
			}
		}

		//serverclosed = true
		//elapsed = time.Since(start)

		close(backenddie)
	}()

	// Pipes data from our client to the remote server
	clientdie := make(chan struct{})
	go func() {
		// Wrap the backend connection so that we can enforce an idle timeout.
		idleconn := &IdleTimeoutConn{
			Conn: client,
			IdleTimeout: server.IdleTimeout,
			Deadline: time.Now().Add(time.Duration(server.MaxTimeout) * time.Second)}


		// DEBUG: To pipe the client request to stderr
		//fmt.Println("[DEBUG] Request follows:")
		//spyconnection := &SpyConnection{client}
		//n, err := copyData(backend, spyconnection)

		// This should be uncommented for production code
		n, err := copyData(backend, idleconn)
		//fmt.Printf("[DEBUG] Request was %d bytes long\n", n)

		// broken pipe = client broke the connection (typically by closing browser tab)
		// i/o timeout = frequently seen with websockets and other connections which try to keep themselves open
		if err != nil && !strings.Contains(err.Error(), "broken pipe") && !strings.Contains(err.Error(), "i/o timeout") {
			if server.network.Logger != nil {
				server.network.Logger.Error("ShadowServer.Fuse()", "Error transferring from client->backend", err, "Addr", host,  "Bytes", n, "Local", server.network.Name[0:10])
			}
		}
		//if !serverclosed {
		//	elapsed = time.Since(start)
		//}
		close(clientdie)
	}()

	// Wait for both connections to close before shutting the tunnel down. Otherwise we can end up
	// in a race condition where the client request ends and shuts the tunnel down.
	<-backenddie
	<-clientdie

	elapsed = time.Since(start)

	return elapsed
	//fmt.Printf("[DEBUG] Fuse() terminated.\n")
}

// SpyConnection embeds a net.Conn, all reads and writes are output to stderr
type SpyConnection struct {
	net.Conn
}

// Read writes all data read from the underlying connection to stderr
func (sc *SpyConnection) Read(b []byte) (int, error) {
	tr := io.TeeReader(sc.Conn, os.Stderr)
	br, err := tr.Read(b)
	return br, err
}

// Write writes all data written to the underlying connection to stderr
func (sc *SpyConnection) Write(b []byte) (int, error) {
	mw := io.MultiWriter(sc.Conn, os.Stderr)
	bw, err := mw.Write(b)
	return bw, err
}

// Copy data between two connections
func copyData(dst net.Conn, src net.Conn) (int64, error) {
	defer dst.Close()
	defer src.Close()

	n, err := io.Copy(dst, src)

	//if err != nil {
		//fmt.Printf("fuse: %d bytes copied.\n", n)
	//}

	return n, err

}

func GetServerConfig() (*ShadowServerConfig) {
	config := &ShadowServerConfig{}
	//config.Listen = ":8011"
	//config.Target = c.String("target")
	//config.Key = "testpassword"
	config.Crypt = "aes-128"
	config.Mode = "fast3"
	config.MTU = 1350
	config.SndWnd = 2048
	config.RcvWnd = 2048
	config.DataShard = 70
	config.ParityShard = 30
	config.DSCP = 46	// "Critical" - see https://en.wikipedia.org/wiki/Differentiated_services#Commonly_used_DSCP_values
	config.NoComp = false
	config.AckNodelay = true
	config.NoDelay = 0
	config.Interval = 50
	config.Resend = 0
	config.NoCongestion = 0
	config.SockBuf = 4194304
	config.KeepAlive = 10
	config.Log = ""
	//config.SnmpLog = ""
	//config.SnmpPeriod = 60
	//config.Pprof = false
	config.Quiet = false

	// Client settings
	config.AutoExpire = 60
	config.ScavengeTTL = 600
	config.Conn = 1

	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}

	return config

}
// Compressed stream used to maximize performance
type compStream struct {
	conn *kcp.UDPSession
	w    *snappy.Writer
	r    *snappy.Reader
	ReadMeter func(uint64)
	WriteMeter func(uint64)
}

func (c *compStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *compStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	//fmt.Printf("[DEBUG] compStream.Write - %d - WriteMeter: %v\n", n,  c.WriteMeter)
	if n > 0 && c.WriteMeter != nil {
		c.WriteMeter(uint64(n))
	}
	return n, err
}

func (c *compStream) Close() error {
	return c.conn.Close()
}

// Extends UDPSession to provide compression
func newCompStream(conn *kcp.UDPSession) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	c.ReadMeter = c.conn.ReadMeter
	c.WriteMeter = c.conn.WriteMeter
	//fmt.Printf("[DEBUG] newCompStream  Compstream=%p  UDPSession=%p  CompStream.WriteMeter=%p   UDPSession.WriteMeter=%p\n", c, &(c.conn),  c.WriteMeter, c.conn.WriteMeter)

	return c
}

func (c *compStream) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
