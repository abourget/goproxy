/* Copyright (C) Winston Privacy, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Richard Stokes <rich@winstonprivacy.com>, November 2018
*/

// Dynamically maps hosts (TLD+1 domains) to the peers their requests should be routed through.
// The hostmap updates dynamically as peers enter and leave the network.
package shadownetwork

import (
	//"fmt"
	"github.com/orcaman/concurrent-map"
	"sync"
	"math/rand"
	"time"
	"sort"
)

const maxhostmapentries = 1000		// Max number of entries allowed in hostmap. Not strictly enforced.
const idlehostexpires = 600		// Inactive hosts removed after this time
const cleaninterval = 10		// Don't clean more frequently than this

type Hostmap struct {
	Host      		cmap.ConcurrentMap
	mu			sync.RWMutex		// Protects Host during clean
	network 		*ShadowNetwork		// Pointer to owner
	nextclean		time.Time
	MaxEntries 		int			// defaults to maxhostmapentries. Caller may update at any time.
	CleanInterval 	int		// 0 = clean every time.
}

type HostmapEntry struct {
	Key1 		string
	Key2		string
	Expires		time.Time
}

func (h *Hostmap) Init(sn *ShadowNetwork) {
	h.Host = cmap.New()
	h.network = sn
	h.MaxEntries = maxhostmapentries
	h.CleanInterval = cleaninterval
}

// Caller must hold lock or panics will occur!
func (h *Hostmap) verifypeerwithlock(key string) (bool) {
	//fmt.Println("verifypeerwithlock", key)
	if key=="" {
		return false
	}
	// Check the private transport map
	if t, ok := h.network.PrivateTransport[key]; ok {
		//fmt.Println("verifypeerwithlock found key. Available?", t.Available)
		if t.Available && t.Password.Borrowed < t.Password.AllocatedBytes {
			//fmt.Println("verifypeerwithlock was available")
			// Transport was found, is available and has bytes available.
			return true
		}
	}
	//fmt.Println("verifypeerwithlock did not find key")
	return false
}
// Returns an available transport id. Expects hostname without port.
// If it returns blank, a transport is not available.
func (h *Hostmap) GetTransport(host string) (string) {
	// See if host exists.
	h.network.mu.RLock()
	defer h.network.mu.RUnlock()
	if tmp, ok := h.Host.Get(host); ok {
		entry := tmp.(HostmapEntry)
		entry.Expires = time.Now().Add(time.Second * time.Duration(idlehostexpires))
		//fmt.Println("[DEBUG] GetTransport - new expires", entry.Expires, "host", host)
		// Select one of the hosts at random.
		r := rand.Intn(2)
		//fmt.Println("[DEBUG] GetTransport - random", r, "host", host)
		if r == 0 {
			// Select the first node and failover to the second
			valid := h.verifypeerwithlock(entry.Key1)
			//fmt.Println("[DEBUG] GetTransport 1 - valid", valid)
			if valid {
				h.Host.Set(host, entry)	// Update the expires time
				return entry.Key1
			}
			// TODO: Do we need to rewrite it to Host?
			entry.Key1 = ""
			valid = h.verifypeerwithlock(entry.Key2)
			if valid {
				h.Host.Set(host, entry)	// Update the expires time and delete the first node
				return entry.Key2
			}
		} else {
			// Select the second node and failover to the first
			valid := h.verifypeerwithlock(entry.Key2)
			//fmt.Println("[DEBUG] GetTransport 2 - valid", valid)
			if valid {
				h.Host.Set(host, entry)	// Update the expires time
				return entry.Key2
			}
			// TODO: Do we need to rewrite it to Host?
			entry.Key2 = ""
			valid = h.verifypeerwithlock(entry.Key1)
			if valid {
				h.Host.Set(host, entry)	// Update the expires time
				return entry.Key1
			}
		}
	}

	// Neither node was valid. Reselect them.
	keys := h.GetKey(2)
	//fmt.Println("[DEBUG] GetTransport - num keys", len(keys))
	if len(keys) == 0 {
		// No available transports
		return ""
	}
	newentry := HostmapEntry{
		Key1: keys[0],
		Expires: time.Now().Add(time.Second * time.Duration(idlehostexpires)),
	}
	if len(keys) == 2 {
		newentry.Key2 = keys[1]
	}

	h.Host.Set(host, newentry)

	// To avoid repeating the above logic, just return node 1 when we reselect
	return keys[0]
}

// Housekeeping for the hostmap.
// Called by AddTransport() as this is a convenient time
// Returns number of entries deleted or modified
func (h *Hostmap) Clean() (int) {
	//fmt.Println("[DEBUG] Hostmap.Clean()...")
	// Don't clean more frequently than every X seconds
	if h.nextclean.After(time.Now()) {
		return 0
	}
	nummodified := 0
	// Get current list of active transports
	var transportkeys []string
	h.network.mu.RLock()
	for k, t := range h.network.PrivateTransport {
		if t.Available {
			transportkeys = append(transportkeys, k)
		}
	}
	h.network.mu.RUnlock()


	h.mu.Lock()
	defer h.mu.Unlock()

	var deletekeys []string

	// Loop through each entry on the hostmap
	for item := range h.Host.Iter() {
		k := item.Key
		v := item.Val.(HostmapEntry)

		//fmt.Println("[DEBUG] Clean k", k, "v", v)

		// Delete entry if expired
		if v.Expires.Before(time.Now()) {
			deletekeys = append(deletekeys, k)
		} else {
			//  Clear key1 and key2 if not on active transport list
			var foundkey1, foundkey2 bool
			for _, transportkey := range transportkeys {
				//fmt.Println("[DEBUG] Looking for", transportkey, "Key1", v.Key1, "Key2", v.Key2)
				if v.Key1 != "" && v.Key1 == transportkey {
					//fmt.Println("Found Key 1")
					foundkey1 = true
				}
				if v.Key2 != "" && v.Key2 == transportkey {
					//fmt.Println("Found Key 2")
					foundkey2 = true
				}
			}
			if !foundkey1 {
				v.Key1 = ""
			}
			if !foundkey2 {
				v.Key2 = ""
			}
			if !foundkey1 || !foundkey2 {
				nummodified++
				h.Host.Set(k, v)
			}
		}
	}

	// Delete any keys we previously identified.
	for _, key := range deletekeys {
		nummodified++
		h.Host.Remove(key)
	}


	// TODO: If length of the hostmap exceeds max, sort and remove expiring entries until we recover enough room
	numhosts := h.Host.Count()
	if numhosts > h.MaxEntries {
		//fmt.Println("[DEBUG] Hostmap - exceeded max size. Cleaning expiring entries.")
		type hostexpire struct {
			host 	string
			expires time.Time
		}
		var entries []hostexpire

		// Loop through each entry on the hostmap
		for item := range h.Host.Iter() {
			k := item.Key
			v := item.Val.(HostmapEntry)
			entries = append(entries, hostexpire{host: k, expires: v.Expires})
		}

		sort.Slice(entries, func(i, j int) bool {
			return entries[i].expires.Before(entries[j].expires)
		})

		numtodelete := numhosts - h.MaxEntries + (h.MaxEntries / 5)
		//fmt.Println("[DEBUG] Deleting ", numtodelete)

		// Delete
		for i := 0; i < numtodelete; i++ {
			nummodified++
			h.Host.Remove(entries[i].host)
		}

	}

	h.nextclean = time.Now().Add(time.Second * time.Duration(h.CleanInterval))
	return nummodified
}

// Perform random weighted selection on transports based on their remaining available bandwidth
func (h *Hostmap) GetKey(number int) []string {
	var ret []string
	if number > 2 {
		number = 2
	}

	transportkeys := h.network.GetAvailableBandwidthWithLock()

	// Special case: No transports available.
	if len(transportkeys) == 0 {
		return ret
	}

	// Special case: Only one transport available. Return it.
	if len(transportkeys) == 1 {
		ret = append(ret, transportkeys[0].Key)
		return ret
	}

	// Special case: Request two transports and only two are available. Return them.
	if len(transportkeys) == 2 && number == 2 {
		ret = append(ret, transportkeys[0].Key)
		ret = append(ret, transportkeys[1].Key)
		return ret
	}

	// Generate proportional allocations for each key
	// Loop through each and calculate the total
	var total uint64
	for _, tk := range transportkeys {
		total += tk.Bandwidth
	}

	r := randomuint64(total)

	var skip int
	for ind, tk := range transportkeys {
		if tk.Bandwidth > r {
			// If bandwidth is more than r, select this key. Don't subtract because uint64 will wrap around 0.
			ret = append(ret, tk.Key)
			total -= tk.Bandwidth
			skip = ind
			break
		} else {
			// Bandwidth was less than r, so we can safely subtract and try again.
			r -= tk.Bandwidth
		}
	}

	if number == 1 {
		return ret
	}

	// Select a second node, but skip the first one we selected.
	r = randomuint64(total)
	for ind, tk := range transportkeys {
		if ind != skip {
			if tk.Bandwidth > r {
				// If bandwidth is more than r, select this key. Don't subtract because uint64 will wrap around 0.
				ret = append(ret, tk.Key)
				total -= tk.Bandwidth
				skip = ind
				break
			} else {
				// Bandwidth was less than r, so we can safely subtract and try again.
				r -= tk.Bandwidth
			}
		}
	}

	return ret
}

// Helper function to return random uint64 up to max
const helpermaxInt64 uint64 = 1 << 63 - 1

func randomuint64(max uint64) uint64 {
	return randomHelper(max)
}

func randomHelper(n uint64) uint64 {
	if n < helpermaxInt64 {
		return uint64(rand.Int63n(int64(n+1)))
	}
	x := rand.Uint64()
	for x > n {
		// Reselect as long as we're over the max
		x = rand.Uint64()
	}
	return x
}