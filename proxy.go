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

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
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
	upstream     *listener
	srcIP, dstIP net.IPAddr
	target       net.IP
	status       sessionStatus
	expiry       time.Time
}

type ndp struct {
	target       net.IP
	icmpType     icmp.Type
	srcIP, dstIP net.IPAddr
	payload      []byte
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

var IPV6SolicitedNode = net.IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0, 0, 0}

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

	switch n.icmpType {
	case ipv6.ICMPTypeNeighborAdvertisement:
		for i, s := range sessions {
			if s.target.Equal(target) && sessions[i].status == waiting {
				vlog.Printf("advert, using existing session for target %s\n", target)
				sessions[i].status = valid
				sessions[i].expiry = time.Now().Add(ttl)
				n.dstIP = s.srcIP
				extChan <- n
				return sessions
			}
		}
	case ipv6.ICMPTypeNeighborSolicitation:
		if !n.dstIP.IP.IsMulticast() {
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
					n.icmpType = ipv6.ICMPTypeNeighborAdvertisement
					n.dstIP = n.srcIP
					n.srcIP.IP = nil
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
					srcIP:    n.srcIP,
					dstIP:    n.dstIP,
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

	var c net.PacketConn
	c, err = net.ListenPacket("ip6:58", "::") // ICMP for IPv6
	if err != nil {
		return
	}

	defer c.Close()

	p := ipv6.NewPacketConn(c)
	err = p.SetControlMessage(ipv6.FlagSrc|ipv6.FlagDst, true)
	if err != nil {
		return
	}

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

	var f ipv6.ICMPFilter
	f.SetAll(true)
	f.Accept(ipv6.ICMPTypeNeighborSolicitation)
	f.Accept(ipv6.ICMPTypeNeighborAdvertisement)
	err = p.SetICMPFilter(&f)
	if err != nil {
		return
	}

	errChan := make(chan error)

	go func() {
		for {
			payload := make([]byte, snaplen)
			i, rcm, src, err := p.ReadFrom(payload)
			if err != nil {
				// send an error if it's encountered
				errChan <- err
				return
			}
			var target net.IP
			// IPv6 bounds check
			if len(payload) >= 16 {
				target = net.IP(payload[:16])
			} else {
				continue
			}
			// 58 protocol number for IPv6-ICMP
			rm, err := icmp.ParseMessage(58, payload[:i])
			if err != nil {
				return
			}

			var srcIP *net.IPAddr
			srcIP, err = net.ResolveIPAddr(src.Network(), src.String())
			if err != nil {
				return
			}
			var dstIP *net.IPAddr
			dstIP.IP = rcm.Dst
			n := ndp{target: target, icmpType: rm.Type, dstIP: *dstIP, srcIP: *srcIP, payload: payload}
			// send data if we read some.
			l.intChan <- n
			vlog.Printf("%s\tread\t%s\tip6_src %s\tip6_dst %s\ttarget %s\n", l.ifname, n.icmpType, n.srcIP.IP, n.dstIP.IP, n.target)
		}
	}()

	for {
		select {

		case err = <-errChan:
			return
		case n, ok := <-l.extChan:
			if !ok {
				// channel was closed
				return
			}

			wm := icmp.Message{
				Type: n.icmpType, Code: 0,
				Body: &AdvertSolicit{
					icmpType: n.icmpType,
					target:   n.target,
				},
			}

			var wb []byte
			wb, err = wm.Marshal(nil)
			if err != nil {
				return
			}

			var wcm ipv6.ControlMessage
			wcm.Src = linklocal
			wcm.HopLimit = 255 // as per RFC
			_, err = p.WriteTo(wb, &wcm, &n.dstIP)
			if err != nil {
				return
			}

			vlog.Printf("%s\twrite\t%s\tip6_src %s\tip6_dst %s\ttarget %s\n", l.ifname, n.icmpType, n.srcIP.IP, n.dstIP.IP, n.target)
		}
	}
}

type AdvertSolicit struct {
	icmpType icmp.Type
	target   net.IP
}

// Len implements the Len method of MessageBody interface.
func (p *AdvertSolicit) Len(proto int) int {
	if p == nil {
		return 0
	}
	// first 4 bytes reserved, IP, options
	return 4 + 16 + 2
}

// Marshal implements the Marshal method of MessageBody interface.
func (p *AdvertSolicit) Marshal(proto int) ([]byte, error) {

	// first 4 bytes reserved, IP, options
	b := make([]byte, 4+16+2)
	switch p.icmpType {
	case ipv6.ICMPTypeNeighborSolicitation:
		// source link-layer address opt type, opt length
		b = append(b[:4], p.target...)
		b = append(b[:20], 0x01, 0x01)
	case ipv6.ICMPTypeNeighborAdvertisement:
		// router,solicit,override flags
		b[0] = 0xc0
		// target link-layer address opt type, opt length
		b = append(b[:4], p.target...)
		b = append(b[:20], 0x02, 0x01)
	}

	return b, nil
}
