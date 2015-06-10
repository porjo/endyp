package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

const routeRefreshInterval = 30

type ndp struct {
	typ   uint8
	iface string
}

type iface struct {
	name      string
	relayChan chan ndp
}

func Proxy(wg *sync.WaitGroup, ifname string, rules []string) {

	defer wg.Done()
	var upstreams []iface
	lastRefresh := time.Now()

	mainif := iface{name: ifname, relayChan: make(chan ndp)}
	go Listen(mainif, nil)
	for {
		if time.Since(lastRefresh) >= time.Duration(routeRefreshInterval)*time.Second {
			for _, rule := range rules {
				ip, _, err := net.ParseCIDR(rule)
				if err != nil {
					fmt.Printf("Invalid rule '%s', error: %s\n", rule, err)
					return
				}
				routes, err := netlink.RouteGet(ip)
				if err != nil || len(routes) == 0 {
					// route not found, skip
					continue
				}
				links, err := netlink.LinkList()
				if err != nil {
					fmt.Printf("Error enumerating links, error: %s\n", err)
					return
				}
				for _, link := range links {
					for _, route := range routes {
						if link.Attrs().Index == route.LinkIndex {
							iff := iface{name: link.Attrs().Name, relayChan: make(chan ndp)}
							upstreams = append(upstreams, iff)
						}
					}
				}
			}
			for _, upstream := range upstreams {
				go Listen(upstream, mainif.relayChan)
			}
			lastRefresh = time.Now()
		}

		select {
		case n := <-mainif.relayChan:

		}

	}
}

func Listen(iff iface, ndpChan chan ndp) {
	var eth layers.Ethernet
	var ip6 layers.IPv6
	var icmp layers.ICMPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &icmp)
	decoded := []gopacket.LayerType{}
	if handle, err := pcap.OpenLive(iff.name, snaplen, true, 0); err != nil {
		fmt.Printf("pcap open error: %s\n", err)
		return
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			parser.DecodeLayers(packet.Data(), &decoded)
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
					case layers.ICMPv6TypeNeighborSolicitation:
						fmt.Printf("Solicit target %s, src %s, dst %s\n", target, ip6.SrcIP, ip6.DstIP)
						ndpChan <- ndp{layers.ICMPv6TypeNeighborSolicitation, iff.name}
					case layers.ICMPv6TypeNeighborAdvertisement:
						fmt.Printf("Advertise target %s, src %s, dst %s\n", target, ip6.SrcIP, ip6.DstIP)
						ndpChan <- ndp{layers.ICMPv6TypeNeighborAdvertisement, iff.name}
					}
				}
			}
		}
	}
}
