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

const routeCheckInterval = 30

type listener struct {
	sync.RWMutex
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
	ifname  string
	payload gopacket.Payload
	icmp    layers.ICMPv6
	ip6     layers.IPv6
	eth     layers.Ethernet
}

const (
	waiting sessionStatus = iota
	valid
	invalid

	ttl = time.Duration(500 * time.Millisecond)
)

func Proxy(wg *sync.WaitGroup, ifname string, rules []string) {
	defer wg.Done()

	var err error
	upstreams := make(map[string]*listener)
	// shared channels upstreams send to
	errChan := make(chan error)
	intChan := make(chan ndp)
	mainInChan := make(chan ndp)
	tickChan := time.NewTicker(time.Second * routeCheckInterval).C

	var sessions []session

	// launch handler for main interface 'ifname'
	l := &listener{intChan: intChan, extChan: mainInChan, errChan: errChan}
	go l.Handler(ifname)

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
			sessions = proxyPacket(ifname, n, mainInChan, upstreams, sessions)
		case <-tickChan:
			sessions = updateSessions(sessions)
			err := refreshRoutes(rules, intChan, errChan, upstreams)
			if err != nil {
				fmt.Printf("%s\n", err)
				return
			}
		}
	}
}

func proxyPacket(ifname string, n ndp, mainInChan chan ndp, upstreams map[string]*listener, sessions []session) []session {
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
			if s.target.Equal(target) {
				sessions[i].status = valid
				n.ip6.DstIP = s.srcIP
				mainInChan <- n
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
					s.upstream.extChan <- n
				}
				return sessions
			}
		}

		var s *session
		// if msg arrived from the main interface, then send to matching upstreams
		for _, upstream := range upstreams {
			if upstream.ruleNet.Contains(target) {
				s = &session{
					upstream: upstream,
					srcIP:    n.ip6.SrcIP,
					dstIP:    n.ip6.DstIP,
					target:   target,
					status:   waiting,
					expiry:   time.Now().Add(ttl),
				}
			}
		}

		if s != nil {
			sessions = append(sessions, *s)
			s.upstream.extChan <- n
		}
	}

	return sessions
}

func updateSessions(sessions []session) []session {
	log.Printf("update sessions")
	for i := 0; i < len(sessions); i++ {

		if sessions[i].expiry.After(time.Now()) {
			continue
		}

		switch sessions[i].status {
		case waiting:
			sessions[i].status = invalid
			sessions[i].expiry = time.Now().Add(ttl)
		default:
			log.Printf("remove sess %d, target %s", i, sessions[i].target)
			// remove session
			if i == len(sessions)-1 {
				sessions = sessions[:i]
			} else {
				sessions = append(sessions[:i], sessions[i+1:]...)
			}
		}

	}
	return sessions
}

func refreshRoutes(rules []string, intChan chan ndp, errChan chan error, upstreams map[string]*listener) error {
	log.Printf("Refreshing routes...")
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
			if r.Dst.Contains(ruleNet.IP) {
				route = &r
				break
			}
		}

		if route == nil {
			// cancel any proxies for removed routes
			for _, upstream := range upstreams {
				if upstream.ruleNet.IP.Equal(ruleNet.IP) {
					close(upstream.extChan)
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
					log.Printf("New upstream for link '%s', rule '%s', route '%s'\n", link.Attrs().Name, rule, route.Dst)
					upstreams[link.Attrs().Name] = &listener{
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
		if !listener.started {
			// launch handler for an upstream of the main proxy interface
			go listener.Handler(name)
		}
		if listener.finished {
			delete(upstreams, name)
		}
		listener.RUnlock()
	}
	return nil
}

func (l *listener) Handler(ifname string) {
	var err error
	var handle *pcap.Handle
	log.Printf("Spawning listener for if %s\n", ifname)
	l.Lock()
	l.started = true
	l.Unlock()

	defer func() {
		l.Lock()
		l.finished = true
		l.Unlock()
		if err != nil {
			l.errChan <- err
		}
	}()

	handle, err = pcap.OpenLive(ifname, snaplen, true, 0)
	if err != nil {
		err = fmt.Errorf("pcap open error: %s", err)
		return
	}
	defer handle.Close()
	defer func() {
		log.Printf("%s: handler exit %s", ifname, err)
	}()

	var iface *net.Interface
	iface, err = net.InterfaceByName(ifname)
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
		err = fmt.Errorf("error finding link local unicast address for interface %s", ifname)
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
						n := ndp{eth: eth, ip6: ip6, icmp: icmp, ifname: ifname, payload: payload}
						if verbose {
							log.Printf("%s: read ndp %s, ip6 src %s, dst %s, target %s\n", ifname, icmp.TypeCode, ip6.SrcIP, ip6.DstIP, target)
						}
						l.intChan <- n
					}
				}
			}

		case n, ok := <-l.extChan:
			if !ok {
				// channel was closed
				return
			}
			eth := n.eth

			eth.DstMAC = nil
			if n.ip6.DstIP.IsLinkLocalMulticast() {
				// Ethernet MAC is derived by the four low-order octets of IPv6 address
				eth.DstMAC = net.HardwareAddr{0x33, 0x33}
				eth.DstMAC = append(eth.DstMAC, n.ip6.DstIP[12:]...)
			} else {
				var neighbors []netlink.Neigh
				neighbors, err = netlink.NeighList(iface.Index, netlink.FAMILY_V6)
				if err != nil {
					return
				}
				for _, neighbor := range neighbors {
					if neighbor.IP.Equal(n.ip6.DstIP) {
						eth.DstMAC = neighbor.HardwareAddr
					}
				}
			}
			if eth.DstMAC == nil {
				err = fmt.Errorf("could not find destination MAC address for IP %s", n.ip6.DstIP)
				return
			}
			eth.SrcMAC = iface.HardwareAddr
			ipv6 := n.ip6
			ipv6.SrcIP = linklocal
			buf := gopacket.NewSerializeBuffer()
			n.icmp.SetNetworkLayerForChecksum(&ipv6)
			opts := gopacket.SerializeOptions{ComputeChecksums: true}
			switch n.icmp.TypeCode.Type() {
			case layers.ICMPv6TypeNeighborSolicitation:
				// ND solicit opt type, opt length
				n.payload = append(n.payload[:16], 0x01, 0x01)
			case layers.ICMPv6TypeNeighborAdvertisement:
				// ND advert opt type, opt length
				n.payload = append(n.payload[:16], 0x02, 0x01)
				n.icmp.TypeBytes[0] = 0xc0 // router,solicit,override flags
			}
			n.payload = append(n.payload[:18], iface.HardwareAddr...)

			err = gopacket.SerializeLayers(buf, opts, &eth, &ipv6, &n.icmp, &n.payload)
			if err != nil {
				err = fmt.Errorf("serialize layers error: %s", err)
				return
			}

			err = handle.WritePacketData(buf.Bytes())
			if err != nil {
				err = fmt.Errorf("pcap write error: %s", err)
				return
			}
			if verbose {
				log.Printf("%s: write ndp %s, ip6 src %s, dst %s, target %s\n", ifname, n.icmp.TypeCode, ipv6.SrcIP, ipv6.DstIP, net.IP(n.payload[:16]))
			}
		}
	}
}
