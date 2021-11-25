# tcpy
This was going to just be a TCP implementation in python, but I got carried away,
so now it's a full networking stack from ethernet frames up using raw sockets.
It doesn't rely on any OS assistance to the extent I can help it, so it does its
own ARP and DNS lookups without relying on the OS or its cache.

Note that creation of raw sockets requires superuser permissions!

Currently working
* ping
* DNS lookups
* HTTP Requests

Next goals
* Traceroute
* IPv6

## Shortcuts/things not supported
* Doesn't handle out-of-order packets -- it just receives data and ACKs it
* Doesn't wait for ACKs before sending more (and really so far I haven't had to
break up data I'm sending into multiple packets)

## Some interesting things I learned doing this
* The network interface hardware often does its own TCP checksums and segmentation,
but this behavior leads to wireshark reporting that packets' checksums are incorrect
(since it sees them before the hardware can set the correct value).  This can be turned
off using `ethtool -K $interface tx off` and `ethtool -K $interface tso off`.
* Running this in VirtualBox with its standard networking configuration (nat)
doesn't work -- something about how it does NAT clobbers the TCP packets after
the connection is established and subsequent packets are never seen on the other
side (the handshake goes through though).  It worked with a bridged adapter,
though.
