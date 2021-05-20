# tcpy
This was going to just be a TCP implementation in python, but I got carried away,
so now it's a full networking stack from ethernet frames up using raw sockets.
It doesn't rely on any OS assistance to the extent I can help it, so it does its
own ARP and DNS lookups without relying on the OS or its cache.

Next goals
* TCP
* Traceroute
* IPv6


## Some interesting things I learned doing this
* The network interface hardware often does its own TCP checksums and segmentation,
but this behavior leads to wireshark reporting that packets' checksums are incorrect
(since it sees them before the hardware can set the correct value).  This can be turned
off using `ethtool -K $interface tx off` and `ethtool -K $interface tso off`.
