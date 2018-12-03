package conntrack

import (
	"github.com/winstonprivacyinc/go-netdb"

	"net"
)

type TypeFilter uint8

const (
	SNATFilter TypeFilter = 1 << iota
	DNATFilter
	RoutedFilter
	LocalFilter
)

var localIPs = make([]*net.IPNet, 0)

func isLocalIP(ip net.IP) bool {
	for _, localIP := range localIPs {
		if localIP.IP.Equal(ip) {
			return true
		}
	}

	return false
}

func init() {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}

	for _, address := range addresses {
		localIPs = append(localIPs, address.(*net.IPNet))
	}
}

func (flows FlowSlice) Filter(filter func(flow Flow) bool) FlowSlice {
	filtered := make(FlowSlice, 0, len(flows))

	for _, flow := range flows {
		if filter(flow) {
			filtered = append(filtered, flow)
		}
	}

	return filtered
}

func (flows FlowSlice) FilterByType(which TypeFilter) FlowSlice {
	snat := (which & SNATFilter) > 0
	dnat := (which & DNATFilter) > 0
	local := (which & LocalFilter) > 0
	routed := (which & RoutedFilter) > 0

	return flows.Filter(func(flow Flow) bool {
		return ((snat && flow.isSNAT()) ||
			(dnat && flow.isDNAT()) ||
			(local && flow.isLocal()) ||
			(routed && flow.isRouted()))
	})
}

func (flows FlowSlice) FilterByProtocol(protocol *netdb.Protoent) FlowSlice {
	return flows.Filter(func(flow Flow) bool {
		return flow.Protocol.Equal(protocol)
	})
}

func (flows FlowSlice) FilterByState(state string) FlowSlice {
	return flows.Filter(func(flow Flow) bool {
		return flow.State == state
	})
}

func (flow Flow) isSNAT() bool {
	// SNATed flows should reply to our WAN IP, not a LAN IP.
	if flow.Original.Source.Equal(flow.Reply.Destination) {
		return false
	}

	if !flow.Original.Destination.Equal(flow.Reply.Source) {
		return false
	}

	return true
}

func (flow Flow) isDNAT() bool {
	// Reply must go back to the source; Reply mustn't come from the WAN IP
	if flow.Original.Source.Equal(flow.Reply.Destination) && !flow.Original.Destination.Equal(flow.Reply.Source) {
		return true
	}

	// Taken straight from original netstat-nat, labelled "DNAT (1 interface)"
	if !flow.Original.Source.Equal(flow.Reply.Source) && !flow.Original.Source.Equal(flow.Reply.Destination) && !flow.Original.Destination.Equal(flow.Reply.Source) && flow.Original.Destination.Equal(flow.Reply.Destination) {
		return true
	}

	return false
}

func (flow Flow) isLocal() bool {
	// no NAT
	if flow.Original.Source.Equal(flow.Reply.Destination) && flow.Original.Destination.Equal(flow.Reply.Source) {
		// At least one local address
		if isLocalIP(flow.Original.Source) || isLocalIP(flow.Original.Destination) || isLocalIP(flow.Reply.Source) || isLocalIP(flow.Reply.Destination) {
			return true
		}
	}

	return false
}

func (flow Flow) isRouted() bool {
	// no NAT
	if flow.Original.Source.Equal(flow.Reply.Destination) && flow.Original.Destination.Equal(flow.Reply.Source) {
		// No local addresses
		if !isLocalIP(flow.Original.Source) && !isLocalIP(flow.Original.Destination) && !isLocalIP(flow.Reply.Source) && !isLocalIP(flow.Reply.Destination) {
			return true
		}
	}

	return false
}
