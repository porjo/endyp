# endyp

An NDP proxy daemon. Inspired by [ndppd](https://github.com/DanielAdolfsson/ndppd)

Many VPS providers will give you an IPv6 subnet but rather than route it to you, they put it 'on link'. This makes it hard to use IPv6 with things like Docker. An NDP proxy solves this problem by 'bridging' the Docker network with the outside network. You could bridget the 2 networks on an ethernet layer, however many VPS providers filter traffic based on source MAC address, so packets that are not originating from your VPS's MAC will be dropped. Again, an NDP proxy solves that problem too as all packets originate use your VPS's MAC address (rather than the MAC assigned to your container).

Written as a learning exercise. It works, but shouldn't be relied on.

Pull requests welcome!

## Usage

`$ ./endyp -c config.toml`

The config file is similar to ndppd e.g.

```
[interfaces.eth0]
rules = ["dead:beef:1::9c3:0:0/104"]
```

`eth0` is the proxy interface and will forward traffic to the interface matching the IP network listed in `rules`. So, for example, I may have a static route sending `dead:beef:1::9c3:0:0/104` to Docker's `docker0` interface. In this case, NDP will be proxied between `eth0` and `docker0`.
