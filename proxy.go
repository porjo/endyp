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
	ruleIP            net.IP
	started, finished bool
}

type ndp struct {
	ifname string
	packet gopacket.Packet
}

func Proxy(wg *sync.WaitGroup, ifname string, rules []string) {
	defer wg.Done()

	var err error
	upstreams := make(map[string]*listener)
	// shared channel upstreams send to
	errChan := make(chan error)
	outChan := make(chan ndp)
	mainInChan := make(chan ndp)
	tickChan := time.NewTicker(time.Second * routeCheckInterval).C

	go Listen(ifname, &listener{outChan: outChan, inChan: mainInChan, errChan: errChan})

	err = refresh(rules, outChan, errChan, upstreams)
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
			// if msg arrived from the main interface, then send to all upstreams
			if n.ifname == ifname {
				for _, upstream := range upstreams {
					upstream.inChan <- n
				}
			} else { // otherwise send to main interface
				mainInChan <- n
			}
		case <-tickChan:
			err := refresh(rules, outChan, errChan, upstreams)
			if err != nil {
				fmt.Printf("%s\n", err)
				return
			}
		}
	}
}

func refresh(rules []string, outChan chan ndp, errChan chan error, upstreams map[string]*listener) error {
	log.Printf("Refreshing routes...")
	for _, rule := range rules {
		ruleIP, _, err := net.ParseCIDR(rule)
		if err != nil {
			return fmt.Errorf("invalid rule '%s', %s", rule, err)
		}
		routes, err := netlink.RouteGet(ruleIP)
		if err != nil || len(routes) == 0 {
			// cancel any proxies for removed routes
			for _, upstream := range upstreams {
				if upstream.ruleIP.Equal(ruleIP) {
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
						upstreams[link.Attrs().Name] = &listener{inChan: make(chan ndp), ruleIP: ruleIP}
					}
				}
			}
		}
	}
	for name, listener := range upstreams {
		listener.RLock()
		if !listener.started {
			listener.outChan = outChan
			listener.errChan = errChan
			go Listen(name, listener)
		}
		if listener.finished {
			delete(upstreams, name)
		}
		listener.RUnlock()
	}
	return nil
}

// inChan carries messages to be sent from this interface
// outChan carries messages read from interface
func Listen(ifname string, listener *listener) {
	var err error
	var handle *pcap.Handle
	log.Printf("Spawning listener for if %s\n", ifname)
	listener.Lock()
	listener.started = true
	listener.Unlock()
	defer func() {
		listener.Lock()
		listener.finished = true
		listener.Unlock()
		if err != nil {
			listener.errChan <- err
		}
	}()

	handle, err = pcap.OpenLive(ifname, snaplen, true, 0)
	if err != nil {
		err = fmt.Errorf("pcap open error: %s", err)
		return
	}
	defer handle.Close()

	var ip6 layers.IPv6
	var icmp layers.ICMPv6
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ip6, &icmp)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsChan := packetSource.Packets()
	for {
		select {
		case packet := <-packetsChan:
			parser.DecodeLayers(packet.Data(), &decoded)
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeICMPv6:
					// bigendian to littlendian
					typ := uint8(icmp.TypeCode >> 8)
					switch typ {
					case layers.ICMPv6TypeNeighborSolicitation, layers.ICMPv6TypeNeighborAdvertisement:
						n := ndp{packet: packet, ifname: ifname}
						log.Printf("%s: read ndp %v\n", ifname, n)
						listener.outChan <- n
					}
				}
			}

		case n, ok := <-listener.inChan:
			/*
				parser.DecodeLayers(n.packet.Data(), &decoded)
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeICMPv6:
						// bigendian to littlendian
						typ := uint8(icmp.TypeCode >> 8)

						var target net.IP
						// do we have a payload large enough to hold an IPv6 address?
						if len(icmp.BaseLayer.Payload) >= 16 {
							target = net.IP(icmp.BaseLayer.Payload[:16])
						} else {
							target = net.IP(icmp.BaseLayer.Payload)
						}
						switch typ {
						case layers.ICMPv6TypeNeighborSolicitation, layers.ICMPv6TypeNeighborAdvertisement:
							outChan <- ndp{packet: packet, ifname: ifname}
						}
					}
				}
			*/
			if ok {
				err = handle.WritePacketData(n.packet.Data())
				if err != nil {
					err = fmt.Errorf("pcap write error: %s", err)
					return
				}
				log.Printf("%s: wrote ndp %v\n", ifname, n)
			} else {
				return
			}
		}
	}
}
