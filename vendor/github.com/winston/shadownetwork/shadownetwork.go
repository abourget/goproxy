/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, March 2018
*/

/* Sets up the current instance as a node in the Winston shadow privacy network.
 * Performs peer discovery and keeps connection statistics on each.
 * TODO: Add authentication
 *
 * Note: When starting a new relay node, the file ./.nodeid is the default location for the enode id. If an instance is launched from
 * an image, this file must be deleted to regenerate a unique node id.
 */

package shadownetwork

import (
	"fmt"
	"os"
	"net"
	"github.com/winstonprivacyinc/go-ethereum/crypto"
	"github.com/winstonprivacyinc/go-ethereum/p2p"
	"github.com/winstonprivacyinc/go-ethereum/p2p/enode"
	"crypto/ecdsa"
	"net/http"
	"strings"
	"sync"
	"time"
	"strconv"
	"context"
	"bytes"
	"os/exec"	
	log "github.com/winstonprivacyinc/go-ethereum/log"
	"crypto/rand"
	"github.com/winstonprivacyinc/go-ethereum/p2p/netutil"
	"github.com/winstonprivacyinc/dns"
	"crypto/tls"
	//kcp "github.com/xtaci/kcp-go"
	"github.com/winstonprivacyinc/smux"

//"runtime"

)

const (
	numNodes           			= 10			// # of nodes to fetch on each refresh
	refreshInterval	   			= 10			// Refresh closest nodes every X minutes
	passwordExpiration			= "600"			// Password expiration in seconds. Should match IdleConnTimeout.
	defaultPasswordExpirationMinutes	= 10			// Default password expiration time in minutes
	authTimeout				= 12			// Peer will be disconnected if it doesn't reply with an authresp in this many seconds
	expiringsoon				= 15			// Transports expiring wthin X seconds will be ignored when joining.
)

const (
	AuthReq = iota
	AuthResp
)

const ShadowTransportKey = "WinstonShadowTransport"
const PrivateNetworkKey = "UsePrivateNetwork"

type ShadowNetworkConfig struct {
	NodeKeyFilename			string       // Full path to node key file
	BandwidthFilename		string             // Full path to latest bandwidth measurement
	StartNetwork			bool            // If false, network will not start (used for testing purposes)
	Port				string          // port number (default: "7776")
	ForceNodeCreation		bool               // If true, a new node will be created, overwriting any previous private key.
	BootNodes			[]string
	SpeedtestClient			string       // Location of the speedtest-cli program.
	SpeedtestFilename		string             // Location to store the speedtest results
	MockProtocol 			[]p2p.Protocol // If non-nil, will use this protocol. Used for unit testing.
	PasswordExpirationMinutes	int                // Time in minutes that passwords are good for
	Logger 				log.Logger   // Optional logger. If non-nil, will capture logging events for caller.
	Password			string              // If non-nil, then transports will use this hard-coded password. Use for testing only.
	ListenAddr			string            // Leave blank for "127.0.0.1". Provide for unit testing as we currently limit to one Winston device per IP.
	NodeDatabase			string          // If provided, a physical location to store previously discovered peers. Reduces need for bootstrapping.
	DownloadSpeed 			int64		// If provided, will use instead of running speed test. Used for unit testing.
	BandwidthSharePercent   	int                 // Percentage of upload bandwidth to share.
	UseLocalDNSOnly           bool                      // if true, only port 53 will be used to resolve ShadowServer DNS requests
	SkipShadowServer          bool                      // if true, will not run the shadowserver. Used for testing only.
	DefaultTransport          *http.Transport           // Local fallback transport in case something goes wrong
	SuppressPasswordLoop      bool                      // Prevents the password refresh loop from starting. Used for unit testing to prevent race conditions.
	SkipPeerConnectivityCheck 	bool                      // Relay nodes should not verify connectivity of peers. Set to true to suppress checks.
}

// Interface for ShadowNetwork - required for unit testing.
type ShadowNetworkInterface interface {
	PeerInfo() 			[]PeerInfo
	TotalBandwidthAllocation() 	uint64
	DownloadSpeed() 		int64
	UploadSpeed() 		int64
}

// This contains data related to an existing Winston shadow network, including information
// about the local node and its peers
type ShadowNetwork struct {

	Ready            		bool                        // True after initialization is complete.

	// Ethereum private keys are intended to be persistent between runs. The corresponding public key is
	// used as the enode hex string (see below) and other nodes will remember them, so it's better if they
	// don't change. https://github.com/ethereum/devp2p/blob/master/rlpx.md
	nodeKey          		*ecdsa.PrivateKey

	// Ethereum nodes are identified using enode format:
	//    enode://[hex string]@IP:Port
	// The hex string is 128 characters in length. The enode format is used for pointing to bootstrap nodes.
	//
	// This is confusing because nodes are internally assigned 64 byte node ids, which can be found in
	// ShadowNetwork.Server.Self().Id(). This is different than the enode hex string and it cannot be sent
	// to the bootstrap logic. For our purposes, we avoid referencing the node ids and only use the enode.
	// To make this easier, the enode hex string is assigned to Name. Use this for logging and testing.
	Name             		string


	Server		 		*p2p.Server           // The Ethereum P2P server (local node)
	ListenPort	 		string                    // The P2P listening address. Default: 7776
	ServicePort	 		string                   // The ShadowSocks service port. Currently hardcoded to ListenPort + 1

	DefaultTransport 		*http.Transport             // Local fallback transport in case something goes wrong
	PrivateTransport 		map[string]*ShadowTransport // Maintains connection data for outbound peers. key is IP:port.
	mu               		sync.RWMutex                // Protects PrivateTransport and ShadowNetwork getters

	Download         		int64                       // Max downstream bandwidth (bytes/sec)
	Upload           		int64                       // Max upstream bandwidth (bytes/sec)

	PasswordExpirationMinutes	int                         // Time in minutes that passwords are good for
	Passwords			[]Password                  // Keeps list of current passwords
	passwordmu			sync.RWMutex               // Protects the password list
	Logger 				log.Logger            // Optional logger. If non-nil, will capture logging events for caller.
	Password			string                       // If non-nil, then transports will use this hard-coded password. Use for testing only.

	ShadowServer            	*ShadowServer                // The shadow server which processes incoming requests
	PeerStore               	*ShadowPeerStore             // Maintains historical stats for inbound peers.
	ListenAddr               	 string                             // Leave blank for "127.0.0.1"
	// TODO: Buffer this to avoid blocking
	reqAuthReq                	map[string]chan bool               // Used to force an AuthReq to named peer
	NodeDatabase              	string                             // If provided, a physical location to store discovered peers
	BandwidthSharePercent     	int                                // Percentage of upload bandwidth to share (defaults to 30%)
	IsClosed                  	bool
	SkipPeerConnectivityCheck 	bool                               // Relay nodes should not verify connectivity of peers. Set to true to suppress checks.
	nextNodeCheck             	time.Time

	HostMap				Hostmap				   // Coordinates requests to the transports which should serve them
}

type BandwidthConsumed struct {
	DownloadedBytes int64
	UploadedBytes   int64
}

// Getter for Download. Used to enable unit testing.
func (sn *ShadowNetwork) DownloadSpeed() int64 {
	return sn.Download
}

// Getter for Upload. Used to enable unit testing.
func (sn *ShadowNetwork) UploadSpeed() int64 {
	return sn.Upload
}

// Can't find any nodes? Kick the network. Useful for testing.
func (sn *ShadowNetwork) Kick() {
	//fmt.Printf("  *** Renegotiating all transports.\n")
	//sn.Table.Lookup(sn.Server.Self().ID)
	sn.RefreshTransports()
}

// Shuts down the service. Can't be restarted.
func (sn *ShadowNetwork) Close()  {
	// Close down password and bandwidth update loops
	sn.mu.Lock()
	sn.IsClosed = true
	sn.mu.Unlock()

	sn.ShadowServer.Close()
	sn.Server.Stop()

	sn.mu.Lock()
	for _, t := range sn.PrivateTransport {
		t.Close()
	}
	sn.mu.Unlock()

}


// Important: The shadowserver listening port is assumed to be equal to the discover port + 1
// If discovery port is 7776, then the shadowserver port is 7777.
func InitializeShadowNetwork(config *ShadowNetworkConfig) (*ShadowNetwork, error) {
	var sn ShadowNetwork
	sn.PrivateTransport = make(map[string]*ShadowTransport)
	sn.Passwords = make([]Password, 0)
	sn.reqAuthReq = make(map[string]chan bool)

	// Default P2P listening port: 7776
	if len(config.Port) == 0 {
		config.Port = "7776"
	}
	sn.ListenPort = config.Port
	serviceport, _ := strconv.Atoi(config.Port)
	sn.ServicePort = strconv.Itoa(serviceport + 1)

	if len(config.NodeKeyFilename) == 0 {
		config.NodeKeyFilename = "./nodekey"
	}

	if config.PasswordExpirationMinutes == 0 {
		sn.PasswordExpirationMinutes = defaultPasswordExpirationMinutes
	} else {
		sn.PasswordExpirationMinutes = config.PasswordExpirationMinutes
	}

	if len(config.SpeedtestFilename) == 0 {
		config.SpeedtestFilename = "./speedtest"
	}

	if config.BandwidthSharePercent <= 0 || config.BandwidthSharePercent > 100 {
		sn.BandwidthSharePercent = 30
	} else {
		sn.BandwidthSharePercent = config.BandwidthSharePercent
	}

	if config.DefaultTransport == nil {
		sn.DefaultTransport = &http.Transport{}
	} else {
		sn.DefaultTransport = config.DefaultTransport
	}

	//fmt.Printf("[INFO] Sharing %d percent of upload bandwidth.\n", sn.BandwidthSharePercent)

	// Read the existing keypair from disk or generate new ones if they don't exist
	createnewnetwork := true

	_, err := os.Stat(config.NodeKeyFilename)
	//fmt.Printf("  *** looking for existing node key: %s\n", config.NodeKeyFilename)
	// See if it already exists and make sure we can read it.
	if !config.ForceNodeCreation && !os.IsNotExist(err) {
		//fmt.Printf("  *** found existing node key: %s\n", config.NodeKeyFilename)

		// Load the private key
		if sn.nodeKey, err = crypto.LoadECDSA(config.NodeKeyFilename); err != nil {
			fmt.Printf("  *** Couldn't read key [%s]. Generating a new one.\n", config.NodeKeyFilename)
			createnewnetwork = true
		} else {
			createnewnetwork = false
		}
	}

	if createnewnetwork {
		sn.nodeKey, err = crypto.GenerateKey()
		if err != nil {
			fmt.Printf("Couldn't generate private key for shadow network. 1 Network will not start. %+v\n", err)
			return nil, err
		}

		// Save it
		if err = crypto.SaveECDSA(config.NodeKeyFilename, sn.nodeKey); err != nil {
			fmt.Printf("[ERROR] Couldn't save node key. [%s] \n", err)
		}
	}

	if len(config.Password) > 0 {
		sn.Password = config.Password
	}

	if len(config.ListenAddr) > 0 {
		sn.ListenAddr = config.ListenAddr
	}

	sn.NodeDatabase = config.NodeDatabase
	if config.NodeDatabase != "" {
		fmt.Printf("[INFO] Configured a local node database. [%s]\n", config.NodeDatabase)
	}

	sn.PeerStore = &ShadowPeerStore{}
	sn.SkipPeerConnectivityCheck = config.SkipPeerConnectivityCheck

	// Initialize the hostmap. This routes domain lookups to specific private transports.
	sn.HostMap = Hostmap{}
	sn.HostMap.Init(&sn)


	if config.StartNetwork {
		// 2Mb RAM storage. Persist results every 60 seconds.
		sn.PeerStore.Initialize("./peers", 2, 60)


		// We need to measure our bandwidth in order to determine how much we can share with peers. This should be updated on a regular interval.
		// Assumes symmetric connection (same upload speed)
		if config.DownloadSpeed > 0 {
			sn.Download = config.DownloadSpeed
			sn.Upload = config.DownloadSpeed
		} else {
			go bandwidthLoop(&sn, config.SpeedtestClient, config.SpeedtestFilename)
		}

		// TODO: To use discv5, you have to connect to next higher port #. We're already using it for ShadowServer.
		cfg := p2p.Config{
			PrivateKey:   	sn.nodeKey,
			ListenAddr:	sn.ListenAddr + ":" + config.Port,
			Protocols:    	sn.Protocols(),
			MaxPeers:	numNodes,	// TODO: Should this be a separate variable?
			NodeDatabase:	sn.NodeDatabase,
			//AnnounceAddr: realaddr,
			//NetRestrict:  restrictList,
			DiscoveryV5:	false,
		}

		if config.Logger != nil {
			// This will only log events from this file
			sn.Logger = config.Logger
		}

		if config.MockProtocol != nil {
			cfg.Protocols = config.MockProtocol
		}
		// RLS 4/25/2018 - Bootnodes are only used once and if a connection is lost, they won't be attempted again
		// until the next start. While our network is small, set these as static nodes so that we can use them as
		// part of our private network.
		for _, url := range config.BootNodes {
			n, err := enode.ParseV4(url)
			if err != nil {
				fmt.Printf("[WARNING] Ignoring invalid bootnode [%s]\n", url)
				os.Exit(1)
				continue
			} else {
				//fmt.Println("[INFO] Adding bootstrap node", n)
				cfg.BootstrapNodes = append(cfg.BootstrapNodes, n)
			}
		}

		// Bored? Watch Ethereum logs scroll by!
		cfg.Logger = config.Logger

		// Configure the Ethereum p2p Server
		sn.Server = &p2p.Server{
			Config: cfg,
		}
		// Initialize the first password
		p := sn.CurrentPassword()
		//fmt.Printf("[DEBUG] Initial password: %+v\n", p)
		if p == nil {
			os.Exit(1)
		}
		// Start the shadowserver listening service. This must be started before the nodes start finding
		// each other, otherwise we can receive AddTransport() requests without a valid ShadowServer.
		if !config.SkipShadowServer {
			if sn.Logger != nil {
				sn.Logger.Info("ShadowServer starting.", "port", sn.ServicePort)
			}
			sn.ShadowServer, err = StartShadowServer(
				sn.ListenAddr,
				sn.ServicePort,
				sn.CurrentPassword().Password,
				&sn,
				true,
				config.UseLocalDNSOnly)
		} else {
			if sn.Logger != nil {
				sn.Logger.Warn("Skipping ShadowServer.", "Local", sn.Name[0:10])
			}
		}

		// Start the password update loop
		if !config.SuppressPasswordLoop {
			go passwordloop(&sn)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			//fmt.Println("[DEBUG] ShadowNetwork.Server.Start()", sn.Server.ListenAddr, "cfg", cfg.ListenAddr)

			err = sn.Server.Start()
			if err != nil {
				fmt.Printf("[ERROR] Couldn't launch P2P network:  %v\n", err)
			} else {
				// Extract the enode hex string from the NodeInfo object and assign it to the server Name.
				nodeinfo := sn.Server.NodeInfo()
				sn.Name = nodeinfo.Enode[8:136]

				if sn.Logger != nil {
					sn.Logger.Info("ShadowNetwork Hello World", "enode", sn.Name[:10], "listen port", sn.ListenAddr + ":" + sn.ListenPort)
				}

			}

			eventC := make(chan *p2p.PeerEvent)
			sn.Server.SubscribeEvents(eventC)
			// Listen for events
			// Be careful - if the PeerAdded() or PeerDropped() routines block, peers will no longer
			// be added and won't be able to respond to AuthReq/AuthResp messages.
			go func() {
				for {
					peerevent, ok := <-eventC
					if !ok {
						break
					}
					switch peerevent.Type {
					case p2p.PeerEventTypeAdd:
						sn.PeerAdded(peerevent.Peer)
					case p2p.PeerEventTypeDrop:
						sn.PeerDropped(peerevent.Peer)
					}
				}
			}()

		}()

		// Block until ShadowNetwork and ShadowServer are running.
		wg.Wait()
		// Everything worked. Flag the network as being ready.
		if err == nil {
			if sn.Logger != nil {
				sn.Logger.Info("ShadowNetwork started.", "Local", sn.Name[0:10], "port", sn.ServicePort)
			}

			// Initialize private transport list
			go sn.loop()

			sn.mu.Lock()
			sn.Ready = true
			sn.mu.Unlock()
		} else {
			if sn.Logger != nil {
				sn.Logger.Error("ShadowNetwork failed to start", "err", err, "port", sn.ServicePort)
			}
		}


	}

	return &sn, nil
}

func bytesDownloaded() int64 {

	downloadcmd := "cat /sys/class/net/lan1/statistics/tx_bytes"

   	dc, _ := exec.Command("bash", "-c", downloadcmd).Output()
	downconsumed := string(bytes.TrimSpace(dc))

	bytesdownloaded, _ := strconv.ParseInt(downconsumed, 10, 64)
	return bytesdownloaded
}

func bytesUploaded() int64 {

   	uploadcmd := "cat /sys/class/net/lan1/statistics/rx_bytes"
	
	uc, _ := exec.Command("bash", "-c", uploadcmd).Output()
	upconsumed := string(bytes.TrimSpace(uc))
	
	bytesuploaded, _ := strconv.ParseInt(upconsumed, 10, 64)
	return bytesuploaded
}

// Averages the amount of download and upload bandwitdth consumed per second by Winston LAN (home network, lan1 on winston hw 1.0)
func bandwidthConsumedLoop( bc *BandwidthConsumed, timedelta int64 ) {
	bytesdownloaded0 := bytesDownloaded()
	bytesuploaded0 := bytesUploaded()
	
	time.Sleep(time.Duration( timedelta ) * time.Minute)
         
	bytesdownloaded1 := bytesDownloaded()
	bytesuploaded1 := bytesUploaded()
	
	bc.DownloadedBytes = (bytesdownloaded1 - bytesdownloaded0) / (timedelta * 60)
	bc.UploadedBytes = (bytesuploaded1 - bytesuploaded0) / (timedelta * 60)
}

// Takes a new bandwidth estimate.
func bandwidthLoop(sn *ShadowNetwork, speedtestclient string, filename string) {
	for {
		if sn.IsClosed {
			fmt.Printf("[DEBUG] Skipping bandwidth measurement. ShadowNetwork is closed.\n")
			//panic("Shadownetwork was closed in bandwidth loop")
			break
		} else {
			MeasureBandwidth(false, sn, speedtestclient, "winston")
			//time.Sleep(time.Duration(1) * time.Hour)
		}
		time.Sleep(time.Duration(15) * time.Minute)
	}
}

// Performs maintenance on the local data stores:
// 1. Checks to see if our server password has changed
// 2. Checks for expired private transports and attempts to refresh them
// 3. Removes any private transports without connected peers
// 4. Verifies remote peers once per hour
func passwordloop(sn *ShadowNetwork) {
	//fmt.Println("passwordloop() initialized")
	pwd := ""
	if sn.ShadowServer != nil {
		pwd = sn.ShadowServer.password
	}
	//fmt.Printf("[DEBUG] Starting password loop with password [%s]\n", pwd)
	for {
		if sn == nil {
			break
		}

		sn.mu.Lock()
		closed := sn.IsClosed
		sn.mu.Unlock()
		if closed {
			break
		}

		time.Sleep(1 * time.Second)

		// Check to see if our server password has changed.
		currentpassword := sn.CurrentPassword()

		//fmt.Println("[DEBUG] passwordloop()  currentpassword", currentpassword.Password, "old pwd", pwd)
		if currentpassword.Password != pwd {
			// The password has changed, so refresh the ShadowServer
			if sn.Logger != nil {
				sn.Logger.Info("ShadowNetwork.passwordloop()", "Changing password.", pwd, "NewPassword", currentpassword.Password, "Local", sn.Name[0:10])
			}

			if sn.ShadowServer != nil {
				//fmt.Println("[DEBUG] Changed ShadowServer password to", currentpassword.Password)
				sn.ShadowServer.ChangePassword(currentpassword.Password, false)
			}
			pwd = currentpassword.Password
		}
		//fmt.Printf("*** [%s] passwordloop2 - (%d) pwd: %s  new password: %s\n", sn.Name[0:10], i, pwd, currentpassword.Password)

		sn.RemoveExpiredPasswords()
		sn.passwordmu.Lock()
		if sn.NeedsNewPasswordWithoutLock() {
			sn.GenerateNewPasswordWithoutLock()
		}
		sn.passwordmu.Unlock()
		// Check all private transports for expired passwords and try to renegotiate.
		// Manually send AuthReq to remote peer
		sn.mu.Lock()
		for k, tr := range sn.PrivateTransport {
			if !sn.PeerIsConnected(tr.ID) {
				delete(sn.PrivateTransport, k)
			} else {
				//fmt.Printf("[DEBUG] [%s] passwordloop2 - 5.3\n", sn.Name[0:10])
				sn.CheckAndRefreshPassword(tr)
				//fmt.Printf("[DEBUG] [%s] passwordloop2 - 5.4\n", sn.Name[0:10])
			}
		}
		sn.mu.Unlock()
		//fmt.Printf("[DEBUG] [%s] # Private transports I am aware of: %d\n", sn.Name[0:10], len(sn.PrivateTransport))
	}
	//}()
}

func (sn *ShadowNetwork) PeerIsConnected(ID string) (bool) {
	_, err := sn.GetPeer(ID)
	if err == nil {
		return true
	}
	return false
}

func (sn *ShadowNetwork) GetPeer(ID string) (*p2p.Peer, error) {
	for _, peer := range sn.Server.Peers() {
		if peer.ID().String() == ID {
			return peer, nil
		}
	}
	return nil, fmt.Errorf("Peer not found")
}


// Refresh the transport list every 10 minutes. This will happen until we shut down.
func (sn *ShadowNetwork) loop() {
	// Delay so we don't attempt to refresh this while the network is starting.
	time.Sleep(time.Minute)

	//ticker := time.NewTicker(refreshInterval * time.Minute)
	// Update outbound transports every 10 minutes. However, check every 10 seconds.
	ticker := time.NewTicker(10 * time.Second)
	for ; true; <-ticker.C {
		if sn.IsClosed {
			break
		}
		if sn.nextNodeCheck.Before(time.Now()) {
			err := sn.RefreshTransports()

			if err == nil {
				// Flag the network as being ready
				sn.mu.Lock()
				sn.Ready = true

				// Check again in 10 minutes
				sn.nextNodeCheck = time.Now().Add(time.Duration(refreshInterval) * time.Minute)
				sn.mu.Unlock()
				//time.Sleep(time.Duration(refreshInterval) * time.Minute)
			} else {
				// The network wasn't ready yet. Try again shortly.
				if sn.Logger != nil {
					sn.Logger.Debug("ShadowNetwork Loop", "Network not ready. Waiting 15 seconds.\n")
				}
				//time.Sleep(time.Duration(15) * time.Second)
			}
		}
	}
}



/* Bandwidth Negotiation

Connects to each of the closest nodes and then requests bandwidth allocation and password from each.
Remote node should respond with a Shadowsocks connection password, expiration time, and the available bandwidth.
*/

type AuthReqMsg struct {
	Req			bool
}

type AuthRespMsg struct {
	Password		string
	ExpirationSeconds	string
	AllowedBandwidth	string
	ListenAddr		string		// Normally blank, indicating public IP should be used. For unit testing, provides spoofed IP address.
	Port			string
}

//protoW := &sync.WaitGroup{}
//pingW = &sync.WaitGroup{}

// This is the authentication protocol. Run() func called in a separate goroutine after a connection has been
// made to a remote peer. It waits for an AuthReq message and replies with an AuthResp. It also listens for
// AuthResp messages and sets up a private transport if everything is in order. Note that if one of the nodes
// goes down and comes back up, the connection will still be active, so the code to send an AuthReq must live
// elsewhere (RefreshTransports).
func (sn *ShadowNetwork) Run(p *p2p.Peer, rw p2p.MsgReadWriter) error {

	//fmt.Printf("*** Protocol Run(): Local: %+v  Remote: %+v\n", p.LocalAddr(), p.RemoteAddr())

	if sn.Logger != nil {
		sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Starting protocol handler", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
	}

	// TEST: Wait 1 second before starting so that the dial tasks can be processed.
	time.Sleep(time.Second)
	if sn.Logger != nil {
		sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Starting protocol handler continues", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
	}

	// We have two goroutines sending to errC and it's possible a race condition could result either in a panic
	// or a deadlocked goroutine. We could use a third channel to signal to senders that the channel is closed,
	// but in practice this occurs so rarely that we'll just recover() from the occasional panic using safeSend().
	// See: https://go101.org/article/channel-closing.html
	errC := make(chan error)
	receivedC := make(chan bool, 1)

	// Initialize manual AuthReq channel. Callers can send true to this to force an AuthReq.
	sn.reqAuthReq[p.ID().String()] = make(chan bool, 5)


	// Set up a loop to transmit AuthReq every {refreshInterval} minutes
	ticker := time.NewTicker(refreshInterval * time.Minute)

	// Send an AuthReq when we first start the protocol
	sn.reqAuthReq[p.ID().String()] <- true
	go func() {
		if sn.Logger != nil {
			sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Starting AuthReq loop", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
		}
		for {
			// Block until one of these conditions is met
			select {
			case <-ticker.C:
			case <-sn.reqAuthReq[p.ID().String()]:
			}

			// Send a AuthReq
			msg := AuthReqMsg{
				Req:			true,
			}

			// send the message
			//if sn.Logger != nil {
			//	sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Sending AuthReq", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
			//}
			err := p2p.Send(rw, AuthReq, msg)
			// Don't modify or remove. Used by unit tests.
			if sn.Logger != nil {
				sn.Logger.Debug("ShadowNetwork.Run()", "msg", "AuthReq Sent", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
			}
			if err != nil {
				// Transmission failure. Abort the protocol.
				//fmt.Println("Error: ", err)
				if sn.Logger != nil {
					sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Failed to send AuthReq", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10], "err", err)
				}
				safeSendError(errC, err)
				return
			}

			if sn.Logger != nil {
				sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Waiting for AuthResp", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
			}
			// Block until we receive a response or timeout. If we timeout here, we'll disconnect the remote peer.
			select {
			case <-receivedC:
				if sn.Logger != nil {
					sn.Logger.Debug("Run()", "Status", "Received AuthResp.", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
				}
			case <-time.After(time.Second * authTimeout):
				if sn.Logger != nil {
					// Don't modify this message. It's used by unit tests.
					sn.Logger.Debug("ShadowNetwork.Run()", "msg", "AuthResp timeout", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
				}
				//fmt.Printf("[DEBUG] Error 5: %v\n", err)
				safeSendError(errC, err)

				return
			}
		}

		if sn.Logger != nil {
			sn.Logger.Debug("ShadowNetwork.Run()", "msg", "Aborting AuthReq cycle", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
		}
	}()

	// Listen for a reply
	go func() {
		if sn.Logger != nil {
			sn.Logger.Info("Run()", "msg", "Starting AuthResp listener", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
		}
		for {
			if sn.Logger != nil {
				sn.Logger.Info("Run()", "msg", "Waiting for incoming message", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
			}
			msg, err := rw.ReadMsg()
			if sn.Logger != nil {
				sn.Logger.Info("Run()", "msg", "Received incoming message", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
			}
			if err != nil {
				// TODO: We are getting EOF errors here. Possibly because the other node started and sent
				// a message before we could read it?
				// TODO: Should we abort the protocol or simply ignore the message and continue running?
				//fmt.Printf("*** [%s] Error returned from rw.ReadMsg() [%s] [%+v]\n", sn.Name[0:10], p.ID().String()[0:10], err)
				//errC <- err
				if sn.Logger != nil {
					sn.Logger.Error("Run()", "ReadMsg() Error", err.Error(), "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
				}

				safeSendError(errC, err)
				return
			}

			switch msg.Code {
			case AuthReq:
				// decode the message and check the contents
				var decodedmsg AuthReqMsg
				err = msg.Decode(&decodedmsg)
				if err != nil {
					// Note: this must not be changed or unit tests will break.
					if sn.Logger != nil {
						sn.Logger.Debug("Run()", "msg", "Couldn't decode AuthReq", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10], "err", err)
					}
					//errC <- err
					//fmt.Printf("[DEBUG] Error 2: %v\n", err)
					safeSendError(errC, err)
					return
				} else {
					go p2p.Send(rw, AuthResp, sn.AuthResponse(p.ID()))

					if sn.Logger != nil {
						// Do not remove or modify. Used by unit tests.
						sn.Logger.Debug("Run()", "msg", "Sending AuthResp", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
					}
				}
			case AuthResp:
				//fmt.Printf("  Remote address: %d\n", p.RemoteAddr())
				// decode the message and check the contents
				var decodedmsg AuthRespMsg
				err = msg.Decode(&decodedmsg)
				if err != nil {
					if sn.Logger != nil {
						sn.Logger.Debug("Run()", "msg", "Couldn't decode AuthResp", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
					}

					// If we get here then the remote node is sending us an invalid AuthResp either due to
					// being out of date or malevolent reasons. Ban it for 5 minutes.
					go func() {
						addr, ok := p.RemoteAddr().(*net.TCPAddr)
						if ok {
							fmt.Printf("[WARN] Banning remote IP address %s\n", addr.IP)
							sn.Server.BanNode(addr.IP)
							time.Sleep(5 * time.Minute)
							sn.Server.UnbanNode(addr.IP)
						}
					}()

					//fmt.Printf("[DEBUG] Error 1: %v\n", err)
					safeSendError(errC, err)
					//errC <- err
					return
				} else {
					if sn.Logger != nil {
						sn.Logger.Debug("Run()", "msg", "Received valid AuthResp", "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
					}
					// Update our transport list
					receivedC <- true
					//fmt.Println()
					expirationseconds, _ := strconv.Atoi(decodedmsg.ExpirationSeconds)
					addr, ok := p.RemoteAddr().(*net.TCPAddr)
					if decodedmsg.ListenAddr != "" {

						// ListenAddr should only be provided during unit testing. Public IP address is inferred from P2P negotiation protocol otherwise.
						remoteport, _ := strconv.Atoi(decodedmsg.Port)

						addr = &net.TCPAddr{
							IP: net.ParseIP(decodedmsg.ListenAddr),
							Port: remoteport,
						}
						ok = true
					}
					if ok {
						go sn.AddTransport(addr.IP.String(), decodedmsg.Port, p.Info().ID, expirationseconds, decodedmsg.Password, decodedmsg.AllowedBandwidth)
					}
				}
			}
		}
	}()

	// This blocks until we receive an error at which point the protocol will abort.
	ret := <-errC
	close(errC)

	// Close the listener channel
	close(sn.reqAuthReq[p.ID().String()])

	p.Disconnect(p2p.DiscRequested)
	if sn.Logger != nil {
		sn.Logger.Debug("Run()", "msg", "Shutting down AuthReq protocol due to shutdown, error or timeout", "err", ret, "Local", sn.Name[0:10], "Remote", p.ID().String()[0:10])
	}
	return ret

}


// Recovers if we try to send to a closed channel
// See: https://go101.org/article/channel-closing.html
func safeSendError(ch chan error, value error) {
	defer func() {
		recover()
	}()

	ch <- value  // panic if ch is closed
}


// Generates the authentication response
// This includes determining the bandwidth which should be allocated to a given peer for the current password interval.
func (sn *ShadowNetwork) AuthResponse(ID enode.ID) (AuthRespMsg) {
	pw := sn.CurrentPassword()

	if pw == nil {
		panic("AuthReponse() has no current password. If you see this, FIX ME.")
	}

	// This will be a negative time because password expiration is in the future
	expires := time.Since(pw.NotAfter)
	//fmt.Printf("[DEBUG] Expires is: %+v  pw.NotAfter: %+v\n", expires, pw.NotAfter)

	// If the current password is about to expire, then we need to get the next one
	if pw.NotAfter.Before(time.Now().Local().Add(time.Second * expiringsoon)) {
		//fmt.Printf("  *** The current password is about to expire...\n")
		pw = sn.nextPasswordWithoutLock()
		if pw == nil {
			fmt.Printf("  *** There was no future password...\n")
			sn.passwordmu.Lock()
			sn.GenerateNewPasswordWithoutLock()
			pw = sn.nextPasswordWithoutLock()
			sn.passwordmu.Unlock()
		}

		// Give them the maximum number of seconds for the new password (should not include the time before it starts)
		defaultpasswordseconds, _ := strconv.Atoi(passwordExpiration)
		expires = time.Second * time.Duration(-defaultpasswordseconds)
		//fmt.Printf("[DEBUG] Expires is now set to: %+v\n", expires)
	}

	p, _ := sn.PeerStore.Peer(ID.String())

	// If a peer was recently connected, we may not have computed their bandwidth allocation. Do so now.
	// New peers do not have bandwidth allocated to them. Allocate it now.
	if p.MaxBandwidthBytesPerSec() == 0 {
		fmt.Printf("[INFO] [%s] Peer was not allocated any bandwidth. Updating bandwidth allocation table. [%s]\n", sn.Name[0:10], ID.String()[0:10])
		sn.ComputeBandwidthAllocation()
	}

	if p.MaxBandwidthBytesPerSec() == 0 {
		// This should never happen.
		fmt.Printf("[ERROR] [%s] Peer was still not allocated any bandwidth. It won't be able to connect. [%s]\n", sn.Name[0:10], ID.String()[0:10])
	}
	p.AllocateBandwidth(int64(-expires.Seconds()))

	maxbandwidth := p.MaxBandwidthBytesPerSec()
	//fmt.Printf("  *** AuthResponse() called. %d bytes (%d bytes/sec) allocated to ID: %s\n", p.AllocatedBytes, maxbandwidth, ID.String()[0:10])

	//maxbandwidth := sn.Upload * bandwidthSharePercent / 100

	bw := strconv.Itoa(int(maxbandwidth))

	// TODO: Add NotBefore equivalent in case of future password
	return AuthRespMsg{
		ExpirationSeconds: strconv.Itoa(int(-expires.Seconds())), // Can't send time because they may not match
		Password: 		pw.Password,
		AllowedBandwidth: 	bw,
		Port: 			sn.ServicePort,
		ListenAddr:		sn.ListenAddr,
	}
}

func (sn *ShadowNetwork) Protocols() []p2p.Protocol {
	return []p2p.Protocol{{
		Name:    "auth",
		Version: 1,
		Length:  2,
		Run:	sn.Run,
	}}
}


func (sn *ShadowNetwork) RefreshTransports() (error) {
	//fmt.Println("Starting RefreshTransports()")


	if sn.Server == nil || sn.Server.Self() == nil {
		//fmt.Println("  *** Shadow network not ready.")
		return fmt.Errorf("Shadow network not ready.")
	}

	// Get closest nodes
	nodes := sn.Server.Closest(sn.Server.Self().ID(), numNodes)

	//fmt.Printf("RefreshTransports() - nodes found: %d\n", len(nodes))
	if len(nodes) == 0 {
		if sn.Logger != nil {
			sn.Logger.Debug("RefreshTransports()", "no nodes found", "0", "Local", sn.Name[0:10])
		}
	}
	if len(nodes) > 0 {
		if sn.Logger != nil {
			sn.Logger.Debug("RefreshTransports()", "# nodes found", strconv.Itoa(len(nodes)), "Local", sn.Name[0:10])
		}

		for _, node := range nodes {
			// Connect to the node. The crypto handshake and auth messages will happen automatically

			// Add it. This will do nothing if it's already in our network.
			sn.Server.AddPeer(node)
		}

		// TODO: If there are any nodes on the peer list that we didn't connect with, close their connection.
	}

	return nil
}
// Used to prevent panics if we send an authreq to a dead transport.
func safeSendBool(ch chan bool, value bool) {
	defer func() {
		recover()
	}()

	ch <- value  // panic if ch is closed
}

// Checks if the given shadowtransport has expired and if so, triggers a new AuthReq to update its password..
// If multiple attempts have failed, it will disconnect the peer.
// Also performs occasional connectivity checks to ensure that remote peers are responsive.
func (sn *ShadowNetwork) CheckAndRefreshPassword(tr *ShadowTransport) {

	tr.mu.Lock()
	defer tr.mu.Unlock()

	now := time.Now().Local()
	if tr.GoodUntil.Before(now) && tr.NextAuthReq.Before(now) {
		//fmt.Printf("[DEBUG] [%s] CheckAndRefreshPassword 1 \n", sn.Name[0:10])
		if tr.AuthReqsSent >= 3 {
			if tr.AuthReqsSent == 3 {
				if sn.Logger != nil {
					sn.Logger.Debug("CheckAndRefreshPassword()", "Too many AuthReqs sent without response. Removing peer.", tr.AuthReqsSent, "Local", sn.Name[0:10], "Remote", tr.ID[0:10])
				}

				peer, err := sn.GetPeer(tr.ID)
				if err == nil {
					peer.Disconnect(p2p.DiscRequested)
				}
				// Prevent this from happening repeatedly
				tr.AuthReqsSent += 1
			}

		} else {
			// Test: Sending an AuthReq outside of protocol.Run() may be causing deadlocks. Try communicating with channels.
			//sn.reqAuthReq[tr.ID] <- true
			safeSendBool(sn.reqAuthReq[tr.ID], true)

			tr.NextAuthReq = now.Add(time.Second * 15)
			tr.AuthReqsSent += 1
		}
	} else if !sn.SkipPeerConnectivityCheck {
		// Verify the node every hour or when first added
		if tr.Available && tr.LastVerification.Before(time.Now().Local().Add(time.Hour * -1)) {
			go func() {
				hasinternet := false
				tr.LastVerification = time.Now().Local()
				if _, hasinternet = tr.VerifyPeer(sn.Name); !hasinternet {
					// Wait one second and try again
					time.Sleep(time.Second)
					_, hasinternet = tr.VerifyPeer(sn.Name)
				}

				if !hasinternet {
					//fmt.Println("[DEBUG] Transport doesn't have internet connectivity. Setting unavailable.")
					tr.Available = false
					sn.BanPeer(tr.ID, tr.RemoteIP)
					if sn.Logger != nil {
						sn.Logger.Info("ShadowNetwork.CheckAndRefreshPassword()", "Banning peer for failing connectivity check.", "", "Local", sn.Name[0:10], "Remote", tr.ID[0:10])
					}

				}
			}()
		}

	}
}

// Bans a peer for one hour
func (sn *ShadowNetwork) BanPeer(id, ipaddr string) {
	peer, err := sn.GetPeer(id)
	if err == nil {
		peer.Disconnect(p2p.DiscRequested)

		// Ban the peer
		ip, _, err := net.ParseCIDR(ipaddr + "/32")
		if err != nil {
			fmt.Printf("[ERROR] BanPeer() - Invalid IP address [%s]. Cannot ban. err: %v\n", ipaddr, err)
		} else {
			sn.Server.BanNode(ip)
			go func(remoteipaddr net.IP) {
				time.Sleep(time.Hour)
				sn.Server.UnbanNode(remoteipaddr)
			}(ip)
			//fmt.Printf("[DEBUG] Banned peer for one hour [%s] [%s]\n", id[0:10], ipaddr)
		}
	} else {
		fmt.Printf("[ERROR] BanPeer() - Invalid peer id [%s]. Cannot ban. err: %v\n", id[0:10], err)
	}

}

// Adds a transport (or updates an existing one)
// TODO: Should we consider changing the key from IP:port to enode? This would eliminate potential ambiguity from having two Winston nodes on the same ip address, but at different ports.
func (sn *ShadowNetwork) AddTransport(remoteaddr string, port string, ID string, expiresSec int, password string, allowedBandwidth string) (error) {
	if sn.Logger != nil {
		sn.Logger.Debug("ShadowNetwork.AddTransport()", "Adding Transport at", remoteaddr + ":" + port, "password", password, "expiresSec", expiresSec, "allowedBandwidth", allowedBandwidth, "Local", sn.Name[0:10],"Remote", ID[0:10])
	}
	//fmt.Printf("Adding remote transport: enode: %s  remote addr: %s  port: %s  expires: %d  password: %s  allowedBandwidth: %s\n", ID[0:10], remoteaddr, port, expiresSec, password, allowedBandwidth)
	var n *ShadowTransport
	var ok bool

	//
	// Set up cipher. AddTransport is called whenever a new password is generated, so this will update the cipher then as well.
	config := GetServerConfig()

	// TODO: Wait here until the ShadowServer is ready.
	cipher := sn.ShadowServer.generateBlock(password, config.Crypt)

	key := remoteaddr + ":" + port
	sn.mu.RLock()
	n, ok = sn.PrivateTransport[key]
	sn.mu.RUnlock()

	bw, _ := strconv.Atoi(allowedBandwidth)
	// Create a new transport
	if !ok {

		p := Password{
			Password: 	password,
			NotBefore:	time.Now().Local(),
			NotAfter:	time.Now().Local().Add(time.Duration(expiresSec) * time.Second),
			AllocatedBytes: uint64(bw * expiresSec),
		}

		// TEST
		if p.AllocatedBytes < 0 {
			fmt.Println("[FATAL] AddTransport() - AllocatedBytes was negative.", bw, expiresSec, bw * expiresSec, uint64(bw * expiresSec))
			panic("stack trace")
		}

		n = &ShadowTransport{
			ID:             ID,
			RemoteIP:       remoteaddr,
			Port:           port,
			Available:      true,
			Config: 	config,
			FailureReason:	"",
			ConnectionErrors: 0,
			GoodUntil:      time.Now().Local().Add(time.Second * time.Duration(expiresSec)),
			Password:       p,
			Cipher:         cipher,
			AuthReqsSent:	0,
			NextAuthReq:   	time.Now().Local(),
			Bandwidth:      bw,
			/*Transport:	&SimpleRoundTripper{
				sn:		sn,
				remoteaddr:	remoteaddr,
				port:		port,
			},*/
			network:	sn,
		}

		// TODO: Get rid of wrapped transport
		// This inserts the default transport with our custom DialContext. This has to be done in two steps
		// so that the native RoundTripper() method calls our custom DialContext() method.
		t := &KCPTransport{
			PrivateTransport: n,
			DisableKeepAlives: false,
			MaxIdleConns: 500,		// Sanity check. Should never get close to this.
			MaxIdleConnsPerHost: 6, 	// TODO: Experiment
			IdleConnTimeout: 10 * 60,	// Should match password expiration
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,				// Skip Golang's native certificate checking. We do this when we retrieve certs.
				ClientSessionCache: tls.NewLRUClientSessionCache(25),	// Session ticket support
				MinVersion:         tls.VersionTLS11,			// TEST
				MaxVersion:         tls.VersionTLS12,			// TEST
				Renegotiation:      tls.RenegotiateFreelyAsClient,	// TEST
			},

		}

		n.Transport = t

		// Configure the KCP stream muxer. This allows multiple connections streams to run on the same session.
		// By maintaining only one session, we eliminate unnecessary round trips for every new http request.
		// In comparison, ShadowSocks sets up random ports for every request which incurs the overhead of a UDP
		// round trip. This approach also greatly reduces the number of file descriptors in use.

		// Ignore testing ports
		if !(port == "" || port == "0") {

			n.smuxConfig = smux.DefaultConfig()
			n.smuxConfig.MaxReceiveBuffer = n.Config.SockBuf
			n.smuxConfig.KeepAliveInterval = time.Duration(n.Config.KeepAlive) * time.Second

			// Establishes concurrent streaming sessions to the same endpoint
			initializeSessions(n, expiresSec)
			n.chScavenger = make(chan *smux.Session, 128)
			go sn.scavenger(key, n.chScavenger, n.Config.ScavengeTTL)
		}
	} else {
		// Update existing transport. Only overwrite fields which change on new password intervals.
		n.mu.Lock()
		n.Available = true
		n.FailureReason = ""
		n.ConnectionErrors = 0
		n.GoodUntil = time.Now().Local().Add(time.Duration(expiresSec) * time.Second)
		n.AuthReqsSent = 0
		n.NextAuthReq = time.Now().Local()

		p := Password{
			Password: 	password,
			NotBefore:	time.Now().Local(),
			NotAfter:	time.Now().Local().Add(time.Duration(expiresSec) * time.Second),
			AllocatedBytes: uint64(bw * expiresSec),
		}

		// TEST
		if p.AllocatedBytes < 0 {
			fmt.Println("[FATAL] AddTransport() - AllocatedBytes was negative.", bw, expiresSec)
			panic("stack trace")
		}

		n.Password = p
		n.Cipher = cipher

		// Reconnect and update the TTL
		if !(port == "" || port == "0") {
			initializeSessions(n, expiresSec)
		}
		n.mu.Unlock()
	}

	sn.mu.Lock()
	sn.PrivateTransport[key] = n
	sn.mu.Unlock()

	sn.HostMap.Clean()

	return nil
}



type scavengeSession struct {
	session *smux.Session
	ts      time.Time
}

// Recovers expired sessions
func (sn *ShadowNetwork) scavenger(key string, ch chan *smux.Session, ttl int) {
	//fmt.Printf("[INFO] Starting session scavenger for %s\n", key)
	// Wait a few seconds before we start scavenging. This gives brand new transports time to initialize.
	time.Sleep(5 * time.Second)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []scavengeSession
	for {
		// If the transport is no longer present, then stop scavenging
		sn.mu.RLock()
		_, ok := sn.PrivateTransport[key]
		sn.mu.RUnlock()

		//tr.mu.Lock()
		if !ok {
			//fmt.Printf("[INFO] [%s] Transport %s no longer present. Closing its sessions.\n", sn.Name[0:10], key)
			// Close all sessions
			for _, sess := range sessionList {
				if sess.session != nil {
					sess.session.Close()
				}
			}
			break
		}
		//tr.mu.Unlock()
		select {
		case sess := <-ch:
			//fmt.Println("[DEBUG] New session added to scavenger list.")
			sessionList = append(sessionList, scavengeSession{sess, time.Now()})
		case <-ticker.C:
			var newList []scavengeSession
			madechange := false
			for k := range sessionList {
				s := sessionList[k]
				if s.session != nil {
					if s.session.NumStreams() == 0 || s.session.IsClosed() {
						//fmt.Println("[DEBUG] Session has no streams or was marked as closed. Closing.")
						s.session.Close()
						madechange = true
					} else if ttl >= 0 && time.Since(s.ts) >= time.Duration(ttl) * time.Second {
						//fmt.Println("[DEBUG] Session reached max TTL. Closing.")
						s.session.Close()
						madechange = true
					} else {
						newList = append(newList, sessionList[k])
					}
				}
			}
			// Only copy the new list if we made a change to it.
			if madechange {
				//fmt.Println("[DEBUG] Copying new session list")
				sessionList = newList
			}
		}
	}
	//fmt.Printf("[INFO] Stopping session scavenger for %s\n", key)
}


// Returns the ShadowPeer representing a given external IP address. Ignores port number.
// TODO: Winston nodes are currently limited to one per IP address.
func (sn *ShadowNetwork) GetShadowPeerByIP(remoteaddr net.Addr) (*ShadowPeer) {
	//fmt.Printf("[DEBUG] GetShadowPeer(%v)\n", remoteaddr)
	// Resolve IP address to enode.
	ip, _, err := net.SplitHostPort(remoteaddr.String())
	if err == nil && sn.PeerStore != nil {
		sn.mu.RLock()
		defer sn.mu.RUnlock()
		for _, v := range sn.PrivateTransport {
			// Also include alternate IP in reverse lookup for unit testing purposes. This allows us to assign a second IP address to the same peer.
			if v.RemoteIP == ip || v.AltIP == ip {
				//fmt.Printf("[DEBUG] GetShadowPeer() - Found the transport. Key: %s\n", k)
				p, _ := sn.PeerStore.Peer(v.ID)
				//fmt.Printf("[DEBUG] GetShadowPeer() - Peer: %+v\n", p)
				return p
			}
		}
	}

	//fmt.Printf("[WARN] [%s] Couldn't find remote peer in private transport table: %s\n \n", sn.Name[0:10], ip)
	//panic("stack trace")
	return nil
}


// All IPs are assumed to be external unless proven otherwise
// RLS 8/23/2018 - verify.winstonprivacy.com is a special domain used only to confirm remote peers are responsive.
// This domain will not be publicly accessible but allow it anyway.
func isExternal(hostname string) (bool) {
	if strings.HasPrefix(hostname, "verify.winstonprivacy.com") {
		return true
	}

	hasExternalIP := true

	host := stripPort(hostname)

	addrs, err := net.LookupHost(host)
	if err == nil {
		if len(addrs) > 0 {
			// Only lookup the main address. If this is external, then the rest will be as well.
			ip := net.ParseIP(addrs[0])
			if netutil.IsLAN(ip) {
				return false
			}
		}
	} else {
		// Couldn't parse it. Assume it's internal.
		hasExternalIP = false
	}

	return hasExternalIP
}

// returns only the hostname
func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

// Returns an available shadow transport. If none available, returns nil.
// Will not return any transport with a key on the ignore list
func (sn *ShadowNetwork) Transport(host string) (*ShadowTransport) {
	host, _, _ = net.SplitHostPort(host)
	//fmt.Println("[DEBUG] ShadowNetwork:Transport() host=", host)
	key := sn.HostMap.GetTransport(host)
	//tmp, _ := sn.HostMap.Host.Get("127.0.0.1")
	//entry := tmp.(HostmapEntry)
	//fmt.Println("[DEBUG] ShadowNetwork:Transport() Hostmap entry for 127.0.0.1=", entry)
	//fmt.Printf("[DEBUG] ShadowNetwork address %p\n", sn)

	//fmt.Println("[DEBUG] ShadowNetwork:Transport() selected key=", key)
	if key == "" {
		return nil
	}
	return sn.PrivateTransport[key]

	// Get rid of lock and use hostmap.
	//sn.mu.RLock()
	//defer sn.mu.RUnlock()
	//
	//if len(sn.PrivateTransport) > 0 {
	//	key := SelectTransportKey(&sn.PrivateTransport)
	//	//key := SelectTransportKey(&sn.PrivateTransport, ignore)
	//	if key == "" {
	//		return nil
	//	}
	//	return sn.PrivateTransport[key]
	//}
	//return nil
}

// Picks a random transport. If unavailable, tries the remaining transports in order. If none available, returns ""
//func SelectTransportKey(m *map[string]*ShadowTransport, ignore []string) string {
/*func SelectTransportKey(m *map[string]*ShadowTransport) string {
	if len(*m) == 0 {
		return ""
	}

	// Range picks a randomly selected key from the map
	for k, t := range *m {
		// Make sure it is available
		if t.Available {
			// Check the GoodUntil time. If not valid, mark this transport as unavailable.
			if t.GoodUntil.Before(time.Now().Local()) {
				(*m)[k].Available = false
			} else {
				return k
			}

		}
	}

	return ""
}*/

// Divides the available upload bandwidth between all connected peers, updating their allocation.
// TODO: Replace simple allocation method with TFT
func (sn *ShadowNetwork) ComputeBandwidthAllocation() {
	// Avoid panics in unit tests
	if sn==nil || sn.Server==nil {
		return
	}
	// Divide bandwidth between all connected peers
	peers := sn.Server.PeersInfo()
	numpeers := len(peers)
	if numpeers == 0 {
		return
	}

	allocatedbandwidth := sn.TotalBandwidthAllocation() / uint64(numpeers)
	for _, p := range peers {
		peer, _ := sn.PeerStore.Peer(p.ID)
		peer.mu.Lock()
		peer.maxBandwidthBytesPerSec = allocatedbandwidth
		peer.mu.Unlock()
	}
}

func (sn *ShadowNetwork) TotalBandwidthAllocation() uint64 {
	return uint64(sn.Upload) * uint64(sn.BandwidthSharePercent) / 100
}

func (sn *ShadowNetwork) PeerAdded(peer enode.ID) {
	sn.ComputeBandwidthAllocation()
}

func (sn *ShadowNetwork) PeerDropped(peer enode.ID) {
	sn.ComputeBandwidthAllocation()
}

type PeerInfo struct  {
	ID			string
	Addr			string
	Available		bool
	RecentContribution	uint64		// Bytes lent to the remote peer
	MaxBandwidthBytesPerSec	uint64		// theoretical bandwidth (bytes/sec) we would give them right now
	Bandwidth		int64		// current bandwidth (bytes/sec) assigned to us by the remote peer
	Borrowed		uint64		// # of bytes we've used for the current password
	AllocatedBytes		uint64		// Max # of bytes we're allowed to use for the current password
	FailureReason		string		// Explanation for most recent connection failure
	ConnectionErrors	int		// Number of successive connection errors
}

// Returns information about the currently connected peer nodes
func (sn *ShadowNetwork) PeerInfo() []PeerInfo {

	var peerinfo []PeerInfo

	if sn == nil || sn.Server == nil {
		return peerinfo
	}

	peers := sn.Server.PeersInfo()

	for _, p := range peers {
		ip, _, _ := net.SplitHostPort(p.Network.RemoteAddress)

		info := PeerInfo{
			ID:	p.ID[0:10],
			Addr:	ip,
		}

		// Get the associated private transport
		var pt *ShadowTransport
		for _, transport := range sn.PrivateTransport {
			if transport.RemoteIP == ip {
				pt = transport
			}
		}

		// Get the associated ShadowPeer object. Port doesn't matter.
		remoteaddr := &net.TCPAddr{
			IP: net.ParseIP(ip),
			Port: 80,
		}


		sp := sn.GetShadowPeerByIP(remoteaddr)

		if sp != nil {
			// Current max bandwidth (bytes/sec)
			info.MaxBandwidthBytesPerSec = sp.maxBandwidthBytesPerSec

			// Bandwidth contributed in recent window
			info.RecentContribution = sp.RecentContribution
		}

		if pt != nil {
			// Available
			info.Available = pt.Available

			// Bytes borrowed in current password interval
			info.Borrowed = pt.Password.Borrowed

			// Maximum bytes we're allowed to borrow in the current password interval
			info.AllocatedBytes = pt.Password.AllocatedBytes

			// Bandwidth assigned to us by remote peer for current password interface
			info.Bandwidth = int64(pt.Bandwidth)

			info.FailureReason = pt.FailureReason

			info.ConnectionErrors = pt.ConnectionErrors
		}

		peerinfo = append(peerinfo, info)
	}

	return peerinfo
}


// Used by proxies and ShadowServer to bypass local DNS resolution with an upstream server.
func HijackDNS() func(context.Context, string, string) (net.Conn, error) {
	// Configure our DNS servers. The first server is localhost and is used as a default.
	// If the ctx object contains an Upstream key (see package dns), one of the other
	// defined DNS servers will be used instead.
	// 7/3/2018 - The second server has been set to our unblacklisted coreDNS listener on port 54.
	// This still provides encrypted DNS but does not do local host filtering.
	// TODO: Allow user to configure (possibly multiple) upstream DNS servers.


	dialer := HijackedDNSDialer()
	return dialer.DialContext
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


// Loops through the private transport table and returns keys with the current allocated bandwidth.
// Used by HostMap to randomly select transport keys.
type TransportBandwidth struct {
	Key 		string
	Bandwidth	uint64
}

// Caller must hold lock on shadownetwork.mu
func (sn *ShadowNetwork) GetAvailableBandwidthWithLock() []TransportBandwidth {
	ret := []TransportBandwidth{}
	for k, t := range sn.PrivateTransport {
		t.mu.RLock()
		available := t.Available
		t.mu.RUnlock()

		// Transport has expired
		if t.GoodUntil.Before(time.Now().Local()) {
			//fmt.Println("[DEBUG] Transport has expired. Setting unavailable.")
			t.Available = false
		} else if t.GoodUntil.Before(time.Now().Local().Add(expiringsoon * time.Second)) {
			// Expiring soon. Don't count it.
			available = false
		}

		if available {
			t.Password.mu.RLock()
			tb := TransportBandwidth{
				Key: k,
				Bandwidth: t.Password.AllocatedBytes - t.Password.Borrowed,
			}
			t.Password.mu.RUnlock()
			ret = append(ret, tb)

		}
	}
	return ret
}