package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
)

// spanlen should be large enough to capture the layers we're interested in
const snaplen = 100

var confFile = flag.String("c", "config.toml", "config file")

func main() {
	flag.Parse()

	conf, err := ReadConfig(*confFile)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	//fmt.Printf("config %#v\n", conf)

	var wg sync.WaitGroup
	for ifaceName, iface := range conf.Interfaces {
		_, err := netlink.LinkByName(ifaceName)
		if err != nil {
			fmt.Printf("Ignoring link '%s', error: %s\n", iface, err)
			continue
		}
		wg.Add(1)
		go Proxy(&wg, ifaceName, iface.Rules)
	}
	wg.Wait()
}
