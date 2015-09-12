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
	inChan, outChan   chan ndp
	errChan           chan error
	ruleNet           *net.IPNet
	started, finished bool
}

type sessionStatus int

// sessions track clients who've previously sent neighbor solicits
type session struct {
	srcIP, dstIP, target net.IP
	status               sessionStatus
	ttl                  time.Duration
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
	outChan := make(chan ndp)
	mainInChan := make(chan ndp)
	tickChan := time.NewTicker(time.Second * routeCheckInterval).C

	var sessions []session

	// launch handler for main interface 'ifname'
	go handler(ifname, &listener{outChan: outChan, inChan: mainInChan, errChan: errChan})

	err = refreshRoutes(rules, outChan, errChan, upstreams)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	for {
		select {
		case err = <-errChan:
			fmt.Printf("%s\n", err)
			return
		case n := <-outChan:
			var target net.IP
			// IPv6 bounds check
			if len(n.payload) >= 16 {
				target = net.IP(n.payload[:16])
			} else {
				continue
			}

			// if msg arrived from the main interface, then send to matching upstreams
			if n.ifname == ifname {
				for _, upstream := range upstreams {
					if upstream.ruleNet.Contains(target) {
						if n.icmp.TypeCode.Type() == layers.ICMPv6TypeNeighborSolicitation {
							match := false
							for _, s := range sessions {
								if s.target.Equal(target) {

									switch s.status {
									case waiting:
									case invalid:
										break
									case valid:
										match = true
									}
								}
							}
						}
						upstream.inChan <- n
						continue
					}
				}
			} else { // otherwise send to main interface
				if n.icmp.TypeCode.Type() == layers.ICMPv6TypeNeighborAdvertisement {
					for _, s := range sessions {
						if s.target.Equal(target) {
							match = true
							n.ip6.DstIP = s.srcIP
							mainInChan <- n
							break
						}
					}
				}
			}
		case <-tickChan:
			sessions = updateSessions(sessions)
			err := refreshRoutes(rules, outChan, errChan, upstreams)
			if err != nil {
				fmt.Printf("%s\n", err)
				return
			}
		}
	}
}

func updateSessions(sessions []session) []session {
	for i, s := range sessions {

		switch s.status {
		case waiting:
			sessions[i].status = invalid
			sessions[i].ttl = ttl
		default:
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

func refreshRoutes(rules []string, outChan chan ndp, errChan chan error, upstreams map[string]*listener) error {
	log.Printf("Refreshing routes...")
	for _, rule := range rules {
		_, ruleNet, err := net.ParseCIDR(rule)
		if err != nil {
			return fmt.Errorf("invalid rule '%s', %s", rule, err)
		}
		routes, err := netlink.RouteGet(ruleNet.IP)
		if err != nil || len(routes) == 0 {
			// cancel any proxies for removed routes
			for _, upstream := range upstreams {
				if upstream.ruleNet.IP.Equal(ruleNet.IP) {
					close(upstream.inChan)
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
			for _, route := range routes {
				if link.Attrs().Index == route.LinkIndex && route.Gw == nil {
					if _, ok := upstreams[link.Attrs().Name]; !ok {
						log.Printf("New upstream for link %s, rule %s, route %v\n", link.Attrs().Name, rule, route)
						upstreams[link.Attrs().Name] = &listener{
							inChan:  make(chan ndp),
							outChan: outChan,
							errChan: errChan,
							ruleNet: ruleNet,
						}
					}
				}
			}
		}
	}
	for name, listener := range upstreams {
		listener.RLock()
		if !listener.started {
			// launch handler for an upstream of the main proxy interface
			go handler(name, listener)
		}
		if listener.finished {
			delete(upstreams, name)
		}
		listener.RUnlock()
	}
	return nil
}

func handler(ifname string, listener *listener) {
	var err error
	var handle *pcap.Handle
	log.Printf("Spawning listener for if %s\n", ifname)
	listener.Lock()
	listener.started = true
	listener.Unlock()

	handle, err = pcap.OpenLive(ifname, snaplen, true, 0)
	if err != nil {
		err = fmt.Errorf("pcap open error: %s", err)
		return
	}
	defer handle.Close()
	defer func() {
		listener.Lock()
		listener.finished = true
		listener.Unlock()
		if err != nil {
			listener.errChan <- err
		}
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
	var icmp layers.ICMPv6
	var payload gopacket.Payload
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &icmp, &payload)
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
					case layers.ICMPv6TypeNeighborSolicitation:
						n := ndp{eth: eth, ip6: ip6, icmp: icmp, ifname: ifname, payload: payload}
						log.Printf("%s: read ndp %s, ip6 src %s, dst %s, target %s\n", ifname, icmp.TypeCode, ip6.SrcIP, ip6.DstIP, target)
						log.Printf("in payload %x", payload.Payload())
						listener.outChan <- n
					case layers.ICMPv6TypeNeighborAdvertisement:
						n := ndp{eth: eth, ip6: ip6, icmp: icmp, ifname: ifname, payload: payload}
						log.Printf("%s: read ndp %s, ip6 src %s, dst %s, target %s\n", ifname, icmp.TypeCode, ip6.SrcIP, ip6.DstIP, target)
						log.Printf("in payload %x", payload.Payload())
						listener.outChan <- n
					}
				}
			}

		case n, ok := <-listener.inChan:
			if !ok {
				// channel was closed
				return
			}
			eth := n.eth
			eth.SrcMAC = iface.HardwareAddr
			ipv6 := n.ip6
			ipv6.SrcIP = linklocal
			buf := gopacket.NewSerializeBuffer()
			n.icmp.SetNetworkLayerForChecksum(&ipv6)
			opts := gopacket.SerializeOptions{ComputeChecksums: true}
			//opts := gopacket.SerializeOptions{}
			switch n.icmp.TypeCode.Type() {
			case layers.ICMPv6TypeNeighborSolicitation:
				// ND solicit opt type, opt length
				n.payload = append(n.payload[:16], 0x01, 0x01)
				n.payload = append(n.payload[:18], iface.HardwareAddr...)
			case layers.ICMPv6TypeNeighborAdvertisement:
				// ND advert opt type, opt length
				n.payload = append(n.payload[:16], 0x02, 0x01)
				n.payload = append(n.payload[:18], iface.HardwareAddr...)
			}
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
			log.Printf("%s: write ndp %s, ip6 src %s, dst %s, target %s\n", ifname, n.icmp.TypeCode, ipv6.SrcIP, ipv6.DstIP, net.IP(n.payload[:16]))
			log.Printf("out payload %x", n.payload.Payload())
		}
	}
}
