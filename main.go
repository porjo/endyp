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
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/vishvananda/netlink"
)

var confFile = flag.String("c", "config.toml", "config file")

type vlogger struct {
	logger  *log.Logger
	enabled bool
}

func (l *vlogger) Printf(format string, v ...interface{}) {
	if l.enabled {
		l.logger.Printf(format, v...)
	}
}
func (l *vlogger) Println(v ...interface{}) {
	if l.enabled {
		l.logger.Println(v...)
	}
}

var vlog vlogger

func main() {
	flag.BoolVar(&vlog.enabled, "v", false, "verbose output to stderr")
	flag.Parse()

	if vlog.enabled {
		vlog.logger = log.New(os.Stderr, "", 0)
	}

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
