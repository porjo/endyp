package main

import (
	"fmt"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Interfaces map[string]Iface
}

type Iface struct {
	Rules []string
}

func ReadConfig(file string) (conf Config, err error) {
	_, terr := toml.DecodeFile(file, &conf)
	if terr != nil {
		err = fmt.Errorf("error loading config: %s\n", terr)
	}
	return
}
