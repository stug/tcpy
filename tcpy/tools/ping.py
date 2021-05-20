import socket
import sys
import time

from tcpy.dns import get_ip_for_name
from tcpy.icmp import ICMP_TYPE_ECHO_REPLY
from tcpy.icmp import ICMP_TYPE_ECHO_REQUEST
from tcpy.icmp import IcmpDatagram
from tcpy.icmp import IcmpEchoRequestHeaderFields
from tcpy.ip import listen_for_ip_packets
from tcpy.ip import send_ip_packet
from tcpy.ip import IpPacket
from tcpy.ip import IP_FLAGS_DONT_FRAGMENT
from tcpy.util import get_raw_af_packet_socket
from tcpy.util import human_readable_ip_to_int
from tcpy.util import human_readable_ip_from_int
from tcpy.util import is_ip_string


def ping(host):
    sock = get_raw_af_packet_socket()

    if is_ip_string(host):
        destination_host_ip = human_readable_ip_to_int(host)
        human_readable_ip = host
    else:
        destination_host_ip = get_ip_for_name(sock, host)
        human_readable_ip = human_readable_ip_from_int(destination_host_ip)

    request_icmp_datagram = IcmpDatagram(
        type=ICMP_TYPE_ECHO_REQUEST,
        code=0,
        rest_of_header=IcmpEchoRequestHeaderFields(
            sequence_number=1,
        ).to_raw(),
        payload=int(time.time() * 1000).to_bytes(32, byteorder='big'),
    )

    print(f'Pinging {human_readable_ip}')
    send_ip_packet(
        sock=sock,
        protocol=socket.IPPROTO_ICMP,
        destination_ip=destination_host_ip,
        flags=IP_FLAGS_DONT_FRAGMENT,
        payload=request_icmp_datagram.to_raw()
    )
    for packet in listen_for_ip_packets(
        sock,
        source_ip=destination_host_ip,
        protocol=socket.IPPROTO_ICMP,
    ):
        icmp_datagram = IcmpDatagram.from_raw(packet.payload)
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
