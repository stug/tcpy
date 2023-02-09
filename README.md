# tcpy
This was going to just be a TCP implementation in python, but I got carried away,
so now it's a full networking stack from ethernet frames up using raw sockets.
It doesn't rely on any OS assistance to the extent I can help it, so it does its
own ARP and DNS lookups without relying on the OS or its cache.

Currently working
* ping
* DNS lookups
* basic TCP connection active opening and closing

In progress
* HTTP (I can send requests, but something is wrong with putting together responses
composed of multiple packets

Next goals
* Traceroute
* IPv6

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
