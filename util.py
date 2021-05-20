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

# used to specify the protocol for a raw AF_PACKET socket -- tells it to give us
# ALL incoming frames (e.g. not just IP)
ETH_P_ALL = 0x3


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


def get_route_info(destination_ip):
    # does longest prefix match to find the outgoing route's interface and
    # gateway ip for the destination_ip
    # this requires root
    with open('/proc/net/route') as f:
        best_interface_and_ip = (None, None)
        best_mask = -1
        f.readline()  # burn the header row
        for line in f:
            fields = line.strip().split()
            # fields[0] is the interface
            # fields[1] is the destination, and all 0 means the default route.
            # fields[2] is the gateway ip
            # fields[3] is the flags field, and the 2s bit is the RTF_GATEWAY flag
            # fields[7] is the mask for the route
            gateway_ip = socket.htonl(int(fields[2], 16))
            mask = socket.htonl(int(fields[7], 16))
            route_destination = socket.htonl(int(fields[1], 16))
            masked_destination_ip = destination_ip & mask
            masked_route_destination = route_destination & mask
            if (
                masked_destination_ip == masked_route_destination
                and mask > best_mask
            ):
                best_interface_and_ip = (fields[0], gateway_ip)
                best_mask = mask

        return best_interface_and_ip


def get_interface_ip(interface):
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


def get_interface_mac(interface):
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


def get_raw_af_packet_socket():
    # raw AF_PACKET socket gets raw link layer frames -- requires sudo
    sock = socket.socket(
        family=socket.AF_PACKET,
        type=socket.SOCK_RAW,
        proto=socket.htons(ETH_P_ALL),
    )
    # getting the route info for ip 0.0.0.0 gives us the default route
    default_interface, gateway_ip = get_route_info(0)
    sock.bind((default_interface, 0))
    return sock
