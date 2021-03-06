import fcntl
import re
import socket
import struct


# ioctl command to Get InterFace HardWare ADDRess. See `man 2 ioctl_list` and
# `man 7 netdevice`
SIOCGIFHWADDR = 0x00008927

# ioctl command to Get InterFace ADDR
SIOCGIFADDR = 0x00008915

# this is the length of interface names dealt with by the kernel. It's defined
# in the if.h kernel header -- not sure if it varies with architecture.
IFNAMSIZ = 16


def human_readable_ip_from_int(ip_int):
    # convert back to network byte order first so that the octets are in the
    # expected order
    ip_int = socket.ntohl(ip_int)
    octets = []
    for _ in range(4):
        octets.append(str(ip_int & 0xFF))
        ip_int = ip_int >> 8
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


def is_ip_string(string):
    match = re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', string)
    return match is not None


# TODO: everything from here on down in this file could do with some caching


def get_default_route_info():
    # this requires root
    # adapted from https://stackoverflow.com/questions/2761829/python-get-default-gateway-for-a-local-interface-ip-address-in-linux
    with open('/proc/net/route') as f:
        for line in f:
            fields = line.strip().split()
            # fields[1] is the destination, so all 0 means the default route.
            # fields[3] is the flags field, and the 2s bit is the RTF_GATEWAY flag
            if fields[1] == '00000000' and int(fields[3]) & 2 != 0:
                interface = fields[0]
                # /proc/net/route has the gateway as little-endian hex string
                gateway_hex = fields[2]
                gateway_ip = socket.htonl(int(gateway_hex, 16))
                return interface, gateway_ip


def get_ip(interface):
    interface_ascii = interface.encode('ascii')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # `man 7 netdevice` explains this struct and ioctl request
        info = fcntl.ioctl(
            sock.fileno(),
            SIOCGIFADDR,
            struct.pack('24s', interface_ascii[:IFNAMSIZ]),
        )
        # fields are interface name, socket family, 2 bytes of padding that I'm
        # not sure the reason for, ip address (big endian)
        fields = struct.unpack(f'{IFNAMSIZ}s2s2s4s', info)
        return int.from_bytes(fields[3], byteorder='big')


def get_mac(interface):
    interface_ascii = interface.encode('ascii')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # `man 7 netdevice` explains this struct and ioctl request
        info = fcntl.ioctl(
            sock.fileno(),
            SIOCGIFHWADDR,
            struct.pack('24s', interface_ascii[:IFNAMSIZ]),
        )
        # fields are interface name, socket family, mac address (big endian)
        fields = struct.unpack(f'{IFNAMSIZ}s2s6s', info)
        return int.from_bytes(fields[2], byteorder='big')


def checksum(byte_string):
    checksum = 0
    as_int = int.from_bytes(byte_string, byteorder='big')
    while as_int > 0:
        checksum += as_int & 0xFFFF
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        as_int = as_int >> 16
    return ~checksum & 0xFFFF


def print_table(rows):
    num_fields = len(rows[0])
    max_lengths = [0 for _ in range(num_fields)]

    for row in rows:
        assert len(row) == num_fields, 'Table has inconsistent number of fields'
        max_lengths = [
            max(len(row[i]), max_lengths[i]) for i in range(num_fields)
        ]

    field_format_strings = [
        '{:' + '<{}'.format(max_lengths[i]) + '}' for i in range(num_fields)
    ]
    row_format_string = '\t\t'.join(field_format_strings)

    for row in rows:
        print(row_format_string.format(*row))
