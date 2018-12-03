package shadownetwork


/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, February 2018
*/

/*
   ShadowPeer.go provides disk backed persistent storage to keep track of how much bandwidth we contributed to
   remote clients.

   Diskv is not used directly because Read() and Write() incur the overhead of serialization and this is too costly to
   use with normal network operations. Instead, this class works by backing a map of ShadowPeer objects to diskv on a
   regular interval.

   ShadowPeer also listens for peers as they are added or dropped from the network and calculates a dynamic bandwidth
   allocation for them. This allocation is sent via AuthResp to let remote peers know how much bandwidth they may consume.

   TODO: Consider eliminating diskv and occasionally write the map to disk directly. Diskv may be overkill for our purposes.
 */

import (
	"time"
	"bytes"
	"os"
	"log"
	"io/ioutil"
	"encoding/gob"
	"sort"
	"github.com/winstonprivacyinc/diskv"
	"fmt"
	"sync"
	"path/filepath"
	"strings"
	"strconv"
)

type ShadowPeerStore struct {
						  // Used to remember client signatures and activity
	peersdiskv         *diskv.		Diskv
	BasePath           string
	Ready              bool
	PersistIntervalSec int                    // Data will be persisted every x seconds. If zero, it won't be persisted at all.
	mu                 sync.RWMutex
	peer               map[string]*ShadowPeer // In-memory map of active ShadowPeer objects
}

type ShadowPeer struct {
				       // TODO: May not need this. Consider removing.
	ID                      string

				       // Historical bandwidth contribution
	Contribution            map[string]uint64
	RecentContribution      uint64
	LastRequest             time.Time
	CurrentPasswordStart    time.Time
	mu                      sync.RWMutex
	maxBandwidthBytesPerSec uint64 // The instantaneous point-in-time bandwidth allotted to a given node. Updated frequently.
	AllocatedBytes          uint64 // # of bytes available to be consumed by remote peer for current password
}

func (c *ShadowPeer) Summary() string {
	var buffer bytes.Buffer

	buffer.WriteString("Shadow Peer: ")
	buffer.WriteString(c.ID)
	buffer.WriteString("\n")
	buffer.WriteString("Allocated Bytes: ")
	buffer.WriteString(strconv.Itoa(int(c.AllocatedBytes)))
	//buffer.WriteString("Bandwidth used in recent window: ")
	//buffer.WriteString(string(c.Borrowed))
	buffer.WriteString("\n")
	for d, amount := range c.Contribution {
		buffer.WriteString(d)
		buffer.WriteString(": ")
		buffer.WriteString(string(amount))
		buffer.WriteString("\n")
	}
	return buffer.String()
}

// Implementation of sort.interface based on LastRequest

type ShadowPeerlist []ShadowPeer
func (a ShadowPeerlist) Len() (int) 	{return len(a) }
func (a ShadowPeerlist) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ShadowPeerlist) Less(i, j int) bool { return a[i].LastRequest.After(a[j].LastRequest) }



// Outputs recently connected client information to log. If count > 0, displays last X clients.
func (cs *ShadowPeerStore) DisplayClientInfo(count int) {
	// Loop through directory to retrieve signatures
	dir := cs.BasePath

	_, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("  Error: Client directory does not exist. [%s]\n", dir)
			return
		} else {
			log.Printf("  Unexpected error occurred while checking directory [%s] %v\n", dir, err)
			return
		}
	}

	// Flush all clients to disk
	cs.peersdiskv.Persist()

	var peerlist  []ShadowPeer

	files, err := ioutil.ReadDir(dir)
	if err == nil {
		for _, file := range files {
			//log.Printf("\n  Reading file [%s]\n", dir + "/" + file.Name())
			peerstream, err := cs.peersdiskv.Read(file.Name())
			var peer ShadowPeer
			if (err == nil) {
				dec := gob.NewDecoder(bytes.NewReader(peerstream))
				err = dec.Decode(&peer)
				if (err == nil) {
					peerlist = append(peerlist, peer)
				}
			}

		}
	}

	// We now have a list of clients. Display them in order by time.
	if len(peerlist) == 0 {
		log.Printf("     No peers have been seen yet.\n")
	} else {
		sort.Sort(ShadowPeerlist(peerlist))
		if count == 0 || count > len(peerlist) {
			count = len(peerlist)
		}

		for n := 0; n < count; n++ {
			peer := peerlist[n]
			log.Printf(peer.Summary())
		}
	}

}


func (cs *ShadowPeerStore) Initialize(BasePath string, CacheSizeMb int64, PersistIntervalSec int) {
	cs.Ready = false

	// Diskv does not support relative filepaths on all platforms (ie: EC2). If a relative filepath is given,
	// convert it to an absolute path under the current directory
	if strings.HasPrefix(BasePath, "./") {
		//fmt.Printf("[WARN] PeerStore is converting [%s] to absolute path\n", BasePath)
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		exPath := filepath.Dir(ex)
		BasePath = exPath + "/" + BasePath[2:]
		//fmt.Printf("[WARN] New basepath [%s]\n", BasePath)
	}

	cs.BasePath = BasePath
	cs.PersistIntervalSec = PersistIntervalSec

	// If basepath doesn't exist, then create it.
	if _, err := os.Stat(BasePath); os.IsNotExist(err) {
		//fmt.Printf("[INFO] Peer.Initialize() - Creating directory [%s]\n", BasePath)
		// folder doesn't exist. Create it and set permissions.
		err = os.Mkdir(BasePath, 0666)
		if err != nil {
			fmt.Printf("[ERROR] Peer.Initializa() - Couldn't create directory [%+v]\n", err)
		}
	}

	// Make sure its readable.
	os.Chmod(BasePath, 0666)

	cs.peersdiskv = diskv.New(diskv.Options{
		BasePath:     BasePath,
		Transform:    func(s string) []string { return []string{} },
		CacheSizeMax: CacheSizeMb * 1024 * 1024,
		// Debug test - this will cause the client cache to fill up faster
		//CacheSizeMax: 1024 * 1024 / 8,
	})
	//fmt.Println("cs.client: %+v", cs.clients)

	cs.peer = make(map[string]*ShadowPeer)

	// Clean up old records
	// We could potentially have old peers sitting around taking up space as well as old contribution records in
	// recent peers. Clean this up when we initialize.
	d, err := os.Open(BasePath)
	if err == nil {
		defer d.Close()
		fi, err := d.Readdir(-1)
		if err == nil {
			for _, file := range fi {
				id := file.Name()
				if id != "." && id != ".." {
					c, err := cs.Read(id)
					if err == nil {
						if c.LastRequest.Before(time.Now().Local().Add(-7 * 24 * time.Hour)) {
							// The last request was more than 7 days ago. Delete it.
							cs.peersdiskv.Erase(id)
						} else {
							modified := false
							// Remove any old Contribution keys
							for key, _ := range c.Contribution {
								t, err := time.Parse("2006-01-02", key)
								if err == nil {

									if t.Before(time.Now().Local().Add(-7 * 24 * time.Hour)) {
										delete(c.Contribution, key)
										modified = true
									}
								}
							}
							if modified {
								cs.Save(c)
							}
						}
					}
				}

			}
		}

		// Save any changes
		if PersistIntervalSec <= 0 {
			cs.Persist()
			//cs.peersdiskv.Persist()
		}
	}


	if PersistIntervalSec > 0 {
		// Spin up a thread to automatically persist the cache every X seconds
		//fmt.Println("Spinning up cache persist thread")
		ticker := time.NewTicker(time.Second * time.Duration(PersistIntervalSec))
		go func() {
			for {
				select {
				case <-ticker.C:
				//fmt.Println(" *** PERSISTING PEER CACHE *** ")
					cs.Persist()
				}

			}
		}()
	}


	if cs.peersdiskv != nil {
		cs.Ready = true
	}
}

// Resets all recent contributions to 0
func (cs *ShadowPeerStore) ResetRecentContributions() {
	//fmt.Print("  *** ResetRecentContributions")
	for _, p := range cs.peer {
		p.RecentContribution = 0
	}
}

// Gets the peer record. Creates one if it doesn't exist.
// Bool indicates if the peer was found or not
// Note: PeerStore entries are indexed by enode (ie: "8decc12323...") not IP:Port.
func (cs *ShadowPeerStore) Peer(signature string) (*ShadowPeer, bool) {
	//fmt.Printf("[DEBUG] Peerstore.Peer(%s)\n", signature)
	if cs == nil {
		fmt.Println("[ERROR] shadowpeer.go/Peer(): peerstore was nil.")
	}
	if cs.peer == nil {
		cs.peer = make(map[string]*ShadowPeer)
	}
	cs.mu.RLock()
	p, ok := cs.peer[signature]
	cs.mu.RUnlock()
	if !ok {

		createtime := time.Now().Local()
		peer := ShadowPeer{
			LastRequest:		createtime,
			ID: 			signature,
			Contribution:		make(map[string]uint64),
		}
		cs.mu.Lock()
		cs.peer[signature] = &peer
		cs.mu.Unlock()
		//fmt.Printf("[DEBUG] Couldn't find peer. Creating one. %+v\n", peer)

		return &peer, false
	}

	return p, true

}

// Read() should not used directly
func (cs *ShadowPeerStore) Read(signature string) (*ShadowPeer, error) {
	if cs == nil {
		fmt.Println("[ERROR] shadowpeer.go/Read() - peerstore was nil.")
	}
	if cs.peersdiskv == nil {
		fmt.Println("[ERROR] shadowpeer.go/Read() - peerstore.peersdiskv was nil.")
	}
	peerstream, err := cs.peersdiskv.Read(signature)
	var peer ShadowPeer
	if (err != nil) {
		// New record
		createtime := time.Now().Local()
		peer = ShadowPeer{
			LastRequest:		createtime,
			ID: 			signature,
			Contribution:		make(map[string]uint64),
		}

		err = cs.Save(&peer)
		if err != nil {
			return nil, err
		}

	} else {
		// Existing record. Return it.
		dec := gob.NewDecoder(bytes.NewReader(peerstream))
		err = dec.Decode(&peer)
		if err != nil {
			return nil, err
		}
	}


	if &peer == nil {
		fmt.Printf("  *** FATAL ERROR! Peer can't be nil")
	}

	return &peer, nil
}

// Save() should not be used directly
func (cs *ShadowPeerStore) Save(c *ShadowPeer) (error) {

	// Save the peer record
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(c)
	if err != nil {
		return err
	}
	cs.peersdiskv.WriteMem(c.ID, buff.Bytes())

	/*if strings.HasPrefix(c.Signature, "TestSignature333") {
		fmt.Printf("    *** Save: Connections: %d\n", c.BadConnections)
	}*/

	return nil
}

// Saves the in-memory map to diskv
func (cs *ShadowPeerStore) Persist() {

	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Copy the records in memory to diskv
	for _, v := range cs.peer {
		cs.Save(v)
	}

	cs.peersdiskv.Persist()

	// Remove any stale in-memory records
	for k, _ := range cs.peer {
		if cs.peer[k].LastRequest.Before(time.Now().Local().Add(time.Minute * -30)) {
			delete(cs.peer, k)
		}
	}

}

// Converts bandwidth (bytes/sec) to an absolute amount of bytes which can be transferred.
// This should be called whenever the allocation needs to be reset.
func (p *ShadowPeer) AllocateBandwidth (secondsremaining int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	//fmt.Printf("[DEBUG] AllocateBandwidth() called.\n")
	p.AllocatedBytes = p.maxBandwidthBytesPerSec * uint64(secondsremaining)
	// TEST CODE
	if p.AllocatedBytes < 0 {
		fmt.Println("[FATAL] AllocatedBandwidth was negative.", p.maxBandwidthBytesPerSec, secondsremaining)
		panic("stack trace")
	}
}

func (p *ShadowPeer) MaxBandwidthBytesPerSec() (uint64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxBandwidthBytesPerSec
}

// Returns true if a peer has exceeded the number of bytes they are allowed to consume for the current password interval.
func (p *ShadowPeer) BandwidthExceeded() (bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.RecentContribution >= p.AllocatedBytes
}

// Counts the bandwidth which was contributed to a remote peer both historical and for the current password interval.
func (p *ShadowPeer) UpdateContribution(amount uint64) {
	//fmt.Printf("[DEBUG] ShadowPeer.UpdateContribution(%d)  peer [%s]\n", amount, p.ID[0:10])
	if p != nil {
		p.mu.Lock()
		defer p.mu.Unlock()

		// Record recent domains
		if p.Contribution == nil {
			p.Contribution = make(map[string]uint64)
		}

		date := time.Now().Local().Format("2006-01-02")
		pastcontribution, ok := p.Contribution[date]
		if ok {
			p.Contribution[date] = pastcontribution + amount
		} else {
			p.Contribution[date] = amount
		}

		// Reset the recent contribution if it occurred prior to the current password interval
		if p.LastRequest.Before(p.CurrentPasswordStart) {
			p.RecentContribution = amount
		} else {
			p.RecentContribution += amount
		}


		p.LastRequest = time.Now().Local()


		//fmt.Printf("  *** Bandwidth contributed: %d bytes to peer %s. RecentContribution=%d\n", amount, p.ID[0:10], p.RecentContribution)
	}
}

