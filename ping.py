import socket
import sys
import time

from ethernet import EthernetFrame
from ethernet import ETH_P_ALL
from ethernet import ETH_TYPE_IP
from icmp import ICMP_TYPE_ECHO_REPLY
from icmp import ICMP_TYPE_ECHO_REQUEST
from icmp import IcmpDatagram
from icmp import IcmpEchoRequestHeaderFields
from ip import send_ip_packet
from ip import IpPacket
from ip import IP_FLAGS_DONT_FRAGMENT
from util import get_default_route_info
from util import get_ip
from util import get_mac
from util import human_readable_ip_to_int


def ping(host):
    # raw AF_PACKET socket gets raw link layer frames -- requires sudo
    sock = socket.socket(
        family=socket.AF_PACKET,
        type=socket.SOCK_RAW,
        proto=socket.htons(ETH_P_ALL),
    )
    default_interface, gateway_ip = get_default_route_info()
    sock.bind((default_interface, 0))

    destination_host_ip = human_readable_ip_to_int(host)

    request_icmp_datagram = IcmpDatagram(
        type=ICMP_TYPE_ECHO_REQUEST,
        code=0,
        rest_of_header=IcmpEchoRequestHeaderFields(
            sequence_number=1,
        ).to_raw(),
        payload=int(time.time() * 1000).to_bytes(32, byteorder='big'),
    )

    print('PING!')
    send_ip_packet(
        sock=sock,
        protocol=socket.IPPROTO_ICMP,
        destination_ip=destination_host_ip,
        flags=IP_FLAGS_DONT_FRAGMENT,
        payload=request_icmp_datagram.to_raw()
    )

    # TODO: make a wait_for function that lets us wait for packets of a certain
    # type
    while True:
        raw_frame, address = sock.recvfrom(65536)
        parsed_frame = EthernetFrame.from_raw(raw_frame)
        if parsed_frame.ethertype == ETH_TYPE_IP:
            ip_packet = IpPacket.from_raw(parsed_frame.payload)
            if ip_packet.protocol == socket.IPPROTO_ICMP:
                icmp_datagram = IcmpDatagram.from_raw(ip_packet.payload)
                print('PONG!')
                original_timestamp = int.from_bytes(
                    icmp_datagram.payload,
                    byteorder='big',
                    signed=False,
                )
                duration = int(time.time() * 1000) - original_timestamp
                print(f'Received reply in {duration} ms')
                break


if __name__ == '__main__':
    ping(host=sys.argv[1])
