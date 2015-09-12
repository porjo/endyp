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
