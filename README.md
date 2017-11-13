A simple netmap app to serve icmp echo and arp reply.

# Build

Make sure [netmap](https://github.com/luigirizzo/netmap) installed, then:

```
make
```

or build debug:

```
make debug
```

# Use

Run on netmap enabled box:

```
./netmapinetd -i netmap:eth0 -a 172.15.11.9 -m fa:16:3e:92:a2:af
```

Ping from normal box:

```
ping 172.15.11.9
```

or:

```
arping 172.15.11.9
```

You can use warpping to ping from netmap enabled box:

```
warpping -i eth0 -d 172.15.11.9
```

Get `warpping` from [warpcore](https://github.com/NTAP/warpcore).






