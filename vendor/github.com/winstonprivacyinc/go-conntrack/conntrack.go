// Package conntrack allows reading and filtering entries from the
// conntrack table of Netfilter.
// import "honnef.co/go/conntrack"
package conntrack

import (
	"github.com/winstonprivacyinc/go-netdb"

	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
)

type FlowSlice []Flow

type Flow struct {
	Original  Subflow
	Reply     Subflow
	Protocol  *netdb.Protoent
	State     string
	Unreplied bool
	Assured   bool
	TTL       uint64
}

type Subflow struct {
	Source      net.IP
	Destination net.IP
	SPort       int
	DPort       int
	Bytes       uint64
	Packets     uint64
}

func Flows() (FlowSlice, error) {
	flows := make([]Flow, 0)

	data, err := ioutil.ReadFile("/proc/net/ip_conntrack")
	if err != nil {
		return flows, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		var (
			protocolNum        int64
			protocol, state    string
			ttl                uint64
			unreplied, assured bool
			original, reply    map[string]string
		)

		original = make(map[string]string)
		reply = make(map[string]string)
		fields := strings.Fields(line)

		if len(fields) == 0 {
			break
		}

		protocol = fields[0]
		protocolNum, _ = strconv.ParseInt(fields[1], 10, 32)
		ttl, _ = strconv.ParseUint(fields[2], 10, 64)

		if protocol == "tcp" {
			state = fields[3]
		}

		for _, field := range fields[3:] {
			if field == "[UNREPLIED]" {
				unreplied = true
			} else if field == "[ASSURED]" {
				assured = true
			} else {
				kv := strings.Split(field, "=")
				if len(kv) != 2 {
					continue
				}
				_, ok := original[kv[0]]

				var m map[string]string
				if ok {
					m = reply
				} else {
					m = original
				}

				m[kv[0]] = kv[1]
			}
		}

		osport, _ := strconv.ParseUint(original["sport"], 10, 16)
		odport, _ := strconv.ParseUint(original["dport"], 10, 16)
		obytes, _ := strconv.ParseUint(original["bytes"], 10, 64)
		opackets, _ := strconv.ParseUint(original["packets"], 10, 64)

		rsport, _ := strconv.ParseUint(reply["sport"], 10, 16)
		rdport, _ := strconv.ParseUint(reply["dport"], 10, 16)
		rbytes, _ := strconv.ParseUint(reply["bytes"], 10, 64)
		rpackets, _ := strconv.ParseUint(reply["packets"], 10, 64)

		protoent := netdb.GetProtoByNumber(int(protocolNum))
		if protoent == nil {
			return nil, fmt.Errorf("Unknown protocol number %d", protocolNum)
		}

		flow := Flow{
			Original: Subflow{
				Source:      net.ParseIP(original["src"]),
				Destination: net.ParseIP(original["dst"]),
				SPort:       int(osport),
				DPort:       int(odport),
				Bytes:       obytes,
				Packets:     opackets,
			},
			Reply: Subflow{
				Source:      net.ParseIP(reply["src"]),
				Destination: net.ParseIP(reply["dst"]),
				SPort:       int(rsport),
				DPort:       int(rdport),
				Bytes:       rbytes,
				Packets:     rpackets,
			},
			Protocol:  protoent,
			State:     state,
			Unreplied: unreplied,
			Assured:   assured,
			TTL:       ttl,
		}

		if flow.State == "" {
			if flow.Unreplied {
				flow.State = "UNREPLIED"
			} else if flow.Assured {
				flow.State = "ASSURED"
			}
		}
		flows = append(flows, flow)
	}

	return flows, nil
}
