/*
   Copyright 2015 Ian Bishop

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type listener struct {
	sync.RWMutex
	ifname            string
	extChan, intChan  chan ndp
	errChan           chan error
	ruleNet           *net.IPNet
	started, finished bool
}

type sessionStatus int

// sessions track clients who've previously sent neighbor solicits
type session struct {
	upstream             *listener
	srcIP, dstIP, target net.IP
	status               sessionStatus
	expiry               time.Time
}

type ndp struct {
	payload gopacket.Payload
	icmp    layers.ICMPv6
	ip6     layers.IPv6
	eth     layers.Ethernet
}

const (
	waiting sessionStatus = iota
	valid
	invalid

	timeout = time.Duration(500 * time.Millisecond)
	ttl     = time.Duration(30 * time.Second)

	routeCheckInterval = 30

	// snaplen should be large enough to capture the layers we're interested in
	snaplen = 100
)

func Proxy(wg *sync.WaitGroup, ifname string, rules []string) {
	defer wg.Done()

	var err error
	upstreams := make(map[string]*listener)
	// shared channels upstreams send to
	errChan := make(chan error)
	intChan := make(chan ndp)
	mainExtChan := make(chan ndp)
	tickRouteChan := time.NewTicker(time.Second * routeCheckInterval).C
	tickSessChan := time.NewTicker(time.Millisecond * 100).C

	defer func() {
		for _, upstream := range upstreams {
			close(upstream.extChan)
			delete(upstreams, upstream.ifname)
		}
	}()

	var sessions []session

	// launch handler for main interface 'ifname'
	l := &listener{ifname: ifname, intChan: intChan, extChan: mainExtChan, errChan: errChan}
	go l.handler()

	err = refreshRoutes(rules, intChan, errChan, upstreams)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	for {
		select {
		case err = <-errChan:
			fmt.Printf("%s\n", err)
			return
		case n := <-intChan:
			sessions = proxyPacket(n, mainExtChan, upstreams, sessions)
		case <-tickSessChan:
			sessions = updateSessions(sessions)
		case <-tickRouteChan:
			err := refreshRoutes(rules, intChan, errChan, upstreams)
			if err != nil {
				fmt.Printf("%s\n", err)
				return
			}
		}
	}
}

func proxyPacket(n ndp, extChan chan ndp, upstreams map[string]*listener, sessions []session) []session {
	var target net.IP
	// IPv6 bounds check
	if len(n.payload) >= 16 {
		target = net.IP(n.payload[:16])
	} else {
		return sessions
	}

	switch n.icmp.TypeCode.Type() {
	case layers.ICMPv6TypeNeighborAdvertisement:
		for i, s := range sessions {
			if s.target.Equal(target) && sessions[i].status == waiting {
				vlog.Printf("advert, using existing session for target %s\n", target)
				sessions[i].status = valid
				sessions[i].expiry = time.Now().Add(ttl)
				n.ip6.DstIP = s.srcIP
				extChan <- n
				return sessions
			}
		}
	case layers.ICMPv6TypeNeighborSolicitation:
		if !n.ip6.DstIP.IsMulticast() {
			return sessions
		}
		for _, s := range sessions {
			if s.target.Equal(target) {

				switch s.status {
				case waiting, invalid:
					break
				case valid:
					// swap solicit for advert and send back out main interface
					vlog.Printf("solicit, using existing session for target %s\n", target)
					n.icmp.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)
					n.ip6.DstIP = n.ip6.SrcIP
					n.ip6.SrcIP = nil
					extChan <- n
				}
				return sessions
			}
		}

		var s *session
		// if msg arrived from the main interface, then send to matching upstreams
		for _, upstream := range upstreams {
			if upstream.ruleNet.Contains(target) {
				vlog.Printf("session not found when handling solicit for target %s. Creating new session...\n", net.IP(n.payload[:16]))
				s = &session{
					upstream: upstream,
					srcIP:    n.ip6.SrcIP,
					dstIP:    n.ip6.DstIP,
					target:   target,
					status:   waiting,
					expiry:   time.Now().Add(timeout),
				}
			}
		}

		if s != nil {
			if !s.upstream.started {
				// launch upstream handler
				go s.upstream.handler()
			}
			sessions = append(sessions, *s)
			s.upstream.extChan <- n
		}
	}

	return sessions
}

func updateSessions(sessions []session) []session {
	for i := len(sessions) - 1; i >= 0; i-- {

		if sessions[i].expiry.After(time.Now()) {
			continue
		}

		switch sessions[i].status {
		case waiting:
			vlog.Printf("set waiting session %d to invalid, target %s", i, sessions[i].target)
			sessions[i].status = invalid
			sessions[i].expiry = time.Now().Add(ttl)
		default:
			vlog.Printf("remove session %d, target %s", i, sessions[i].target)
			sessions = append(sessions[:i], sessions[i+1:]...)
		}
	}
	return sessions
}

func refreshRoutes(rules []string, intChan chan ndp, errChan chan error, upstreams map[string]*listener) error {
	vlog.Println("refreshing routes...")
	for _, rule := range rules {
		_, ruleNet, err := net.ParseCIDR(rule)
		if err != nil {
			return fmt.Errorf("invalid rule '%s', %s", rule, err)
		}

		routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("error enumerating routes, %s", err)
		}
		var route *netlink.Route
		for _, r := range routes {
			if r.Dst != nil && r.Dst.Contains(ruleNet.IP) {
				route = &r
				break
			}
		}

		if route == nil {
			// cancel any proxies for removed routes
			for _, upstream := range upstreams {
				if upstream.ruleNet.IP.Equal(ruleNet.IP) {
					log.Printf("route for upstream if %s went away. Removing listener...\n", upstream.ifname)
					close(upstream.extChan)
					delete(upstreams, upstream.ifname)
				}
			}
			// route not found, skip
			continue
		}
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("error enumerating links, %s", err)
		}
		for _, link := range links {
			if link.Attrs().Index == route.LinkIndex {
				if _, ok := upstreams[link.Attrs().Name]; !ok {
					log.Printf("new upstream for link '%s', rule '%s', route '%s'\n", link.Attrs().Name, rule, route.Dst)
					upstreams[link.Attrs().Name] = &listener{
						ifname:  link.Attrs().Name,
						extChan: make(chan ndp),
						intChan: intChan,
						errChan: errChan,
						ruleNet: ruleNet,
					}
				}
			}
		}
	}
	for name, listener := range upstreams {
		listener.RLock()
		if listener.finished {
			delete(upstreams, name)
		}
		listener.RUnlock()
	}
	return nil
}

func (l *listener) handler() {
	var err error
	var handle *pcap.Handle
	log.Printf("spawning listener for if %s\n", l.ifname)
	l.Lock()
	l.started = true
	l.Unlock()

	defer func() {
		if err != nil {
			l.errChan <- err
		}
		l.Lock()
		l.finished = true
		l.Unlock()
		log.Printf("exiting listener for if %s\n", l.ifname)
	}()

	// open interface in promiscuous mode in order to pickup solicited-node multicasts
	handle, err = pcap.OpenLive(l.ifname, snaplen, true, pcap.BlockForever)
	if err != nil {
		err = fmt.Errorf("pcap open error: %s", err)
		return
	}
	defer handle.Close()

	var iface *net.Interface
	iface, err = net.InterfaceByName(l.ifname)
	if err != nil {
		return
	}

	var addrs []net.Addr
	var linklocal net.IP
	addrs, err = iface.Addrs()
	if err != nil {
		return
	}

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if v.IP.IsLinkLocalUnicast() {
				linklocal = v.IP
			}
		}
	}

	if linklocal.IsUnspecified() {
		err = fmt.Errorf("error finding link local unicast address for if %s", l.ifname)
		return
	}

	var eth layers.Ethernet
	var ip6 layers.IPv6
	var ip6extensions layers.IPv6ExtensionSkipper
	var icmp layers.ICMPv6
	var payload gopacket.Payload
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &ip6extensions, &icmp, &payload)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsChan := packetSource.Packets()
	for {
		select {
		case packet := <-packetsChan:
			parser.DecodeLayers(packet.Data(), &decoded)
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeICMPv6:
					var target net.IP
					// IPv6 bounds check
					if len(payload) >= 16 {
						target = net.IP(payload[:16])
					} else {
						continue
					}

					switch icmp.TypeCode.Type() {
					case layers.ICMPv6TypeNeighborSolicitation, layers.ICMPv6TypeNeighborAdvertisement:
						n := ndp{eth: eth, ip6: ip6, icmp: icmp, payload: payload}
						vlog.Printf("%s\tread\t%s\tmac_src %s\tip6_src %s\tip6_dst %s\ttarget %s\n", l.ifname, icmp.TypeCode, eth.SrcMAC, ip6.SrcIP, ip6.DstIP, target)
						l.intChan <- n
					}
				}
			}

		case n, ok := <-l.extChan:
			if !ok {
				// channel was closed
				return
			}

			n.eth.DstMAC = nil
			if n.ip6.DstIP.IsLinkLocalMulticast() {
				// Ethernet MAC is derived by the four low-order octets of IPv6 address
				n.eth.DstMAC = append(net.HardwareAddr{0x33, 0x33}, n.ip6.DstIP[12:]...)
			} else {
				var neighbors []netlink.Neigh
				neighbors, err = netlink.NeighList(iface.Index, netlink.FAMILY_V6)
				if err != nil {
					return
				}
				for _, neighbor := range neighbors {
					if neighbor.IP.Equal(n.ip6.DstIP) {
						n.eth.DstMAC = neighbor.HardwareAddr
					}
				}
			}
			if n.eth.DstMAC == nil {
				vlog.Printf("%s: could not find destination MAC address. %s mac_src %s ip6_dst %s ip6_src %s target %s", l.ifname, n.icmp.TypeCode, n.eth.SrcMAC, n.ip6.DstIP, n.ip6.SrcIP, net.IP(n.payload[:16]))
				// Try Solicited-Node multicast address
				// dst IP is derived by the first 13 octets of multicast address +
				// last 3 octets of dst IP
				n.ip6.DstIP = append(net.IPv6linklocalallnodes[:13], n.ip6.DstIP[13:]...)
				n.eth.DstMAC = append(net.HardwareAddr{0x33, 0x33}, n.ip6.DstIP[12:]...)
			}
			n.eth.SrcMAC = iface.HardwareAddr
			n.ip6.SrcIP = linklocal
			buf := gopacket.NewSerializeBuffer()
			n.icmp.SetNetworkLayerForChecksum(&n.ip6)
			opts := gopacket.SerializeOptions{ComputeChecksums: true}
			switch n.icmp.TypeCode.Type() {
			case layers.ICMPv6TypeNeighborSolicitation:
				// source link-layer address opt type, opt length
				n.payload = append(n.payload[:16], 0x01, 0x01)
			case layers.ICMPv6TypeNeighborAdvertisement:
				// target link-layer address opt type, opt length
				n.payload = append(n.payload[:16], 0x02, 0x01)
				n.icmp.TypeBytes[0] = 0xc0 // router,solicit,override flags
			}
			n.payload = append(n.payload[:18], iface.HardwareAddr...)

			err = gopacket.SerializeLayers(buf, opts, &n.eth, &n.ip6, &n.icmp, &n.payload)
			if err != nil {
				err = fmt.Errorf("serialize layers error: %s", err)
				return
			}

			err = handle.WritePacketData(buf.Bytes())
			if err != nil {
				err = fmt.Errorf("pcap write error: %s", err)
				return
			}
			vlog.Printf("%s\twrite\t%s\tmac_dst %s\tip6_src %s\tip6_dst %s\ttarget %s\n", l.ifname, n.icmp.TypeCode, n.eth.DstMAC, n.ip6.SrcIP, n.ip6.DstIP, net.IP(n.payload[:16]))
		}
	}
}
