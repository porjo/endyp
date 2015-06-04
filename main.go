package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var eth layers.Ethernet
	var ip6 layers.IPv6
	var icmp layers.ICMPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &icmp)
	decoded := []gopacket.LayerType{}

	if handle, err := pcap.OpenLive("p1p1", 1600, true, 0); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			parser.DecodeLayers(packet.Data(), &decoded)
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeICMPv6:
					typ := uint8(icmp.TypeCode >> 8)
					var target net.IP
					if len(icmp.BaseLayer.Payload) >= 16 {
						target = net.IP(icmp.BaseLayer.Payload[:16])
					} else {
						target = net.IP(icmp.BaseLayer.Payload)
					}
					switch typ {
					case layers.ICMPv6TypeNeighborSolicitation:
						fmt.Printf("Solicit target %s, src %s, dst %s\n", target, ip6.SrcIP, ip6.DstIP)
					case layers.ICMPv6TypeNeighborAdvertisement:
						fmt.Printf("Advertise target %s, src %s, dst %s\n", target, ip6.SrcIP, ip6.DstIP)
					}
				}
			}
		}
	}
}
