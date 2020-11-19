import socket


def human_readable_ip_from_int(ip_int):
    # convert back to network byte order first so that the octets are in the expected order
    ip_int = socket.ntohl(ip_int)
    octets = []
    for _ in range(4):
        octets.append(str(ip_int & 0xFF))
        ip_int = ip_int >> 8
    # reverse because x86 is little endian and network order is big endian
    return '.'.join(octets)


def human_readable_ip_to_int(ip_address):
    octets = [int(octet) for octet in ip_address.split('.')]
    ip = octets[0]
    for octet in octets[1:]:
        ip = ip << 8
        ip += octet
    # because ip addresses represented as 4 octets are already in network order,
    # we can just return here
    return ip


def get_gateway_ip():
    # this requires root
    # adapted from https://stackoverflow.com/questions/2761829/python-get-default-gateway-for-a-local-interface-ip-address-in-linux
    with open('/proc/net/route') as f:
        for line in f:
            fields = line.strip().split()
            # fields[1] is the destination, so all 0 means the default route.
            # fields[3] is the flags field, and the 2s bit is the RTF_GATEWAY flag
            if fields[1] == '00000000' and int(fields[3]) & 2 != 0:
                # unfortunately /proc/net/route has the gateway as hex string 
                # (in little endian representation)
                gateway_hex = fields[2]
                return socket.htonl(int(gateway_hex, 16))
